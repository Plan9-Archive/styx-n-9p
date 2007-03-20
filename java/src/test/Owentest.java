/*
 * test connection to Owen
 *	Copyright © 2005 Vita Nuova Holdings Limited
 */

import java.math.BigInteger;
import java.nio.*;
import java.nio.channels.*;
import java.io.IOException;
import java.io.*;

import com.vitanuova.owen.*;

public class Owentest {

	public static void main(String[] args) throws Exception {
		if(args.length < 1)
			error("usage: Owentest net!address!infsched [certfile]"); 
		String certfile = "rsacert";
		if(args.length > 1){
			certfile = args[1];
			if(certfile.equals("-"))
				certfile = null;
		}
		Scheduler sched = new Scheduler();
		try{
			sched.connect(args[0], certfile, null, "");
			Jobspec spec = new Jobspec("exec", new String[] {"os", "date"});
			spec.addenum("item", new String[] {"a", "b", "c"});
			spec.addrange("nitem", 10);
			Job job = new Job(sched);
			String dir = job.create();
			System.out.println("job: "+dir+" "+job.uniqueID());
			job.job(spec);
			job.start();
		}catch(SchedulerException e){
			System.out.println("exception during connect: "+e);
			e.printStackTrace();
			error("die");
		}catch(JobException e){
			System.out.println("exception during job start: "+e);
			e.printStackTrace();
			error("die");
		}
	}

	public static String S(byte[] a){
		try{
			return new String(a, "UTF-8");
		}catch(java.io.UnsupportedEncodingException e){
			return "Egosling";
		}
	}

	public static void error(String s){
		System.err.println("Test: "+s);
		System.exit(999);
	}
}
