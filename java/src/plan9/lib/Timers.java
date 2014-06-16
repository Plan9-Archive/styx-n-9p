package plan9.lib;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.*;

public class Timers {
	long time0 = System.currentTimeMillis();	// interval epoch
	LinkedList<Timer> pending = new LinkedList<Timer>();	// pending timeouts
	ReentrantLock lock = new ReentrantLock();
	Condition arriving = lock.newCondition();
	Ticker ticker;

	public interface Action {
		public void timeout();
	}

	public static class Timer {
		int	dt;	// initially, the delta from caller's time base; active, the delta from the previous entry in "pending"
		Action	a;

		Timer(int dt, Action action){
			this.dt = dt; this.a = action;
		}
		synchronized public final void	stop(){
			this.a = null;
		}
		synchronized public final boolean expired(){
			return dt <= 0;
		}
		synchronized public final boolean completed(){
			return this.a == null;
		}
		synchronized final Action action(){
			Action a = this.a;
			this.a = null;
			return a;
		}
	}

	long msec(){
		long dt = System.currentTimeMillis() - time0;
		if(dt < 0){
			// time went backwards. reset interval epoch
			time0 = System.currentTimeMillis();
			dt = 0;
		}
		return dt;
	}

	class Ticker extends Thread {
		long ot;

		Ticker(){
			setDaemon(true);
			Misc.nominate(this);
		}

		final Timer first(){
			lock.lock();
			try{
				while(pending.isEmpty()){
					arriving.await();
					ot = msec();
				}
				return pending.get(0);
			}catch(InterruptedException e){
				return null;
			} finally {
				lock.unlock();
			}
		}

		public final void run(){
			long nt, dt;
			Timer t0;
			ArrayList<Action> todo = new ArrayList<Action>();
		Service:
			while((t0 = first()) != null){
				while(t0.dt > 0){
					lock.lock();
					try{
						arriving.await(t0.dt, TimeUnit.MILLISECONDS);
					}catch(InterruptedException e){
						break Service;
					}finally{
						lock.unlock();
					}
					nt = msec();
					dt = nt-ot;
					ot = nt;
					if(dt < 0)
						continue Service; // time went back, restart
					// a new timer might have been inserted at front meanwhile
					lock.lock();
					try{
						t0 = pending.get(0);
						t0.dt -= dt;
					}finally{
						lock.unlock();
					}
				}
				todo.clear();
				lock.lock();
				try{
					while(!pending.isEmpty() && (t0 = pending.get(0)).dt <= 0){
						todo.add(t0.action());
						pending.remove(0);
					}
				}finally{
					lock.unlock();
				}
				for(Action a : todo)
					if(a != null)
						a.timeout();
			}
		}
	}

	public Timers(){
		ticker = new Ticker();
		ticker.start();
	}

	public final Timer start(int millisec, Action action){
		Timer t = new Timer(millisec, action);
		lock.lock();
		try{
			Timer et = null;
			int i = 0;
			for(; i < pending.size() && (et = pending.get(i)).dt <= t.dt; i++)
				t.dt -= et.dt;
			if(i < pending.size())
				et.dt -= t.dt;
			pending.add(i, t);
			arriving.signal();
		}finally{
			lock.unlock();
		}
		return t;
	}

	public void shutdown(){
		ticker.interrupt();
	}
}
