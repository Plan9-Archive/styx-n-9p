package plan9;

import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class ConsoleLog implements Log {

	static final ConcurrentMap<String,Log> logmap = new ConcurrentHashMap<String,Log>();
	static final long t0 = System.currentTimeMillis();

	final AtomicInteger currentlevel = new AtomicInteger(Off);
	String prefix = "";

	ConsoleLog(){}
	ConsoleLog(String name){ this.prefix = name+": "; }

	public final	Log	newlog(Class tag){
		String name = tag.getName();
		synchronized(this){
			prefix = tag.getName();
			Log l = logmap.get(name);
			if(l == null){
				l = new ConsoleLog(name);
				logmap.put(name, l);
			}
			return l;
		}
	}

	static final String ctime(){
		return String.format("%12d ", System.currentTimeMillis()-t0);
	}
	public final	void	setlevel(int level){
		if(level < 0)
			level = Off;
		if(level > All)
			level = Debug;
		currentlevel.set(level);
	}
	public final boolean logging(){
		return currentlevel.get() != Off;
	}
	public final boolean debugging(){
		return currentlevel.get() >= Debug;
	}
	public final boolean tracing(){
		return currentlevel.get() >= Trace;
	}
	public final void	info(String fmt, Object... things){
		if(currentlevel.get() >= Info)
			System.out.println(ctime()+prefix+String.format(fmt, things));
	}
	public final void	trace(String fmt, Object... things){
		if(currentlevel.get() >= Trace)
			System.out.println(ctime()+prefix+String.format(fmt, things));
	}
	public final void	debug(String fmt, Object... things){
		if(currentlevel.get() >= Debug)
			System.out.println(ctime()+prefix+String.format(fmt, things));
	}
	public final void warn(String fmt, Object... things){
		if(currentlevel.get() >= Warn)
			System.out.println(ctime()+prefix+String.format(fmt, things));
	}
	public final void error(String fmt, Object... things){
		if(currentlevel.get() >= Error)
			System.out.println(ctime()+prefix+String.format(fmt, things));
	}
	public final void fatal(String fmt, Object... things){
		if(currentlevel.get() >= Fatal)
			System.out.println(ctime()+prefix+String.format(fmt, things));
	}
}
