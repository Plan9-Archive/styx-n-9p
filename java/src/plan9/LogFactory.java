package plan9;

import java.util.Map;
import java.util.HashMap;

import plan9.lib.Strings;

import static plan9.Log.*;

public class LogFactory {
	private static boolean checked = false;
	private static Log	thelogger = new ConsoleLog();
	private static Map<String,Integer> levels = new HashMap<String, Integer>();
	private static int defaultlevel = -1;

	public static synchronized Log	logger(Class tag){
		Integer iv;

		if(!checked){
			try{
				Class.forName("org.slf4j.Logger");
				thelogger = new Slf4jLog();
			}catch(ClassNotFoundException e){
				try{
					Class.forName("org.apache.log4j.Logger");
					thelogger = new ApacheLog();
				}catch(ClassNotFoundException e2){
					thelogger = new ConsoleLog();
				}
				defaultlevel = setInitLevels(levels);
			}
			checked = true;
		}
		iv = levels.get(tag.getName());
		Log log = thelogger.newlog(tag);
		if(iv != null)
			log.setlevel(iv.intValue());
		else if(defaultlevel >= 0)	// otherwise take logging system's default
			log.setlevel(defaultlevel);
		return log;
	}

	/*
	 * take debugging levels from environment variable "J9P_DEBUG_LEVEL",
	 * or property "plan9.ninep.loglevel"
	 */
	static final int	setInitLevels(Map<String,Integer> map){
		String ev, s, name;

		ev = System.getenv().get("J9P_DEBUG_LEVEL");
		if(ev == null){
			try{
				ev = System.getProperty("plan9.ninep.loglevel");
			}catch(Exception e){
				// don't care which
				return -1;
			}
		}
		String[] fields = Strings.getfields(ev, ",:\1");	// \1 for rc
		String def = null;
		for(String f : fields){
			String tag = null;
			int sep = f.lastIndexOf('/');
			if(sep >= 0){
				tag = f.substring(0, sep);
				f = f.substring(sep+1);
			}
			if(tag != null && !tag.equals("*") && !tag.equals(""))
				map.put(tag, Integer.valueOf(level(f)));
			else
				def = f;
		}
		if(def != null)
			return level(def);
		return -1;
	}

	static int level(String s){
		if(s.equalsIgnoreCase("fatal"))
			return Fatal;
		else if(s.equalsIgnoreCase("error"))
			return Error;
		else if(s.equalsIgnoreCase("warn"))
			return Warn;
		else if(s.equalsIgnoreCase("info"))
			return Info;
		else if(s.equalsIgnoreCase("debug"))
			return Debug;
		else if(s.equalsIgnoreCase("trace"))
			return Trace;
		else if(s.equalsIgnoreCase("all"))
			return All;
		else if(s.equalsIgnoreCase("off"))
			return Off;
		return -1;
	}
}
