package plan9.lib;

import plan9.Log;
import plan9.LogFactory;
import plan9.lib.Timers;
import static plan9.lib.Timers.Action;
import static plan9.lib.Timers.Timer;

/**
 * Alarms provides a simple way to interrupt a thread (usually the current thread) that takes longer than a specified interval to complete a set of tasks.
 * An instance of the inner class Alarm represents each alarm; its constructor specifies the interval in milliseconds.
 * The interval is expressed in milliseconds, but has no better resolution than the Java system clock.
 *
 * Typical usage:
 *	<code>
 *	import plan9.lib.Alarms;
 *	import static plan9.lib.Alarms.Alarm;
 *	...
 *	Alarm alarm = new Alarm(2*1000);	// alarm in two seconds
 *	try{
 *		operation_subject_to_time_limit();
 *		// operation completed
 *	}catch(InterruptedException e){
 *		// operation did not complete
 *	}finally{
 *		alarm.stop();
 *	}
 *	</code>
 *	<p>
 *	Note that it is often convenient to stop the alarm in a <i>finally</i> clause; it is legal even if the <i>InterruptedException</i> was thrown, when there is no further action to stop.
 *	<p>
 *	Also note that the Java system and the operating system can inject scheduling delays at almost any point, and
 *	the interval chosen should allow for that.
 */
public class Alarms {
	static Timers timers = new Timers();
	private static Log log = LogFactory.logger(Alarms.class);

	static class Interrupt implements Action {
		Thread	t;
		public Interrupt(Thread t){ this.t = t; }
		public void timeout(){
			if(log.tracing())
				log.trace("interrupt "+t.getId()+" "+t.getName());
			 t.interrupt();
		}
	}

	/**
	 * Each instance of Alarm represents one alarm, associating a time limit in milliseconds with a specific thread.
	 * The current thread can be chosen by default.
	 * A new instance must be created for each alarm; alarms are not recurring.
	 */
	public static class Alarm {
		Timer timer;

		/**
		 * Create an alarm to interrupt the current thread in <i>msec</i> milliseconds.
		 */
		public Alarm(int msec){
			this(msec, Thread.currentThread());
		}

		/**
		 * Create an alarm to interrupt the given thread <i>t</i> in <i>msec</i> milliseconds.
		 */
		public Alarm(int msec, Thread t){
			timer = timers.start(msec, new Interrupt(t));
		}

		/**
		 * Stop the alarm and clear the target thread's "interrupted" state.
		 * Note that the alarm might go off during the call, before <i>stop</i> has a chance to stop it,
		 * but not after <i>stop</i> has returned. Stop may be called even if the alarm has gone off,
		 * to allow the operation to be used in a <i>finally</i> clause.
		 */
		public final void stop(){
			if(timer != null){
				timer.stop();
				clear();	// in case it expired before it was stopped
			}
			timer = null;	// discard timer reference
		}

		/** Clear the "interrupted" state of the current thread. */
		public final void clear(){
			if(Thread.interrupted()){
				// ignored
			}
		}

		/** Return true iff the alarm rang */
		public final boolean rang(){
			return timer != null && timer.expired();
		}
	}

	/**
	 * Shut down the alarm system, ending the timer thread.
	 * The timer thread runs as a daemon, so normally there should be no need for an explicit shutdown.
 	 */
	public final static void shutdown(){
		timers.shutdown();
	}
}
