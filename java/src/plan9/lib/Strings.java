package plan9.lib;

import java.util.ArrayList;
import java.util.StringTokenizer;

import java.nio.ByteBuffer;

// from styx-n-9p.googlecode.com (MIT licence)

/**
 * Strings is a little library that offers creation and parsing of quoted strings, breaking a string into fields, and conversion to and from arrays of bytes (as utf-8).
 */
public class Strings {

	private Strings(){}	// no value to create: just static methods

	/** Return <i>s</i> with quotes added as needed in the style of <i>rc</i>(1) to protect spaces and quotes */
	public static final String quote(String s){
		return quote(s, null);
	}

	/** Return <i>s</i> with quotes added as needed in the style of <i>rc</i>(1) to protect spaces, quotes and any other character in a given set */
	public static final String quote(String s, String ccl){
		return quote(new String[] {s}, ccl);
	}

	/** Return a string that has each argument quoted and separated from the next by a single space */
	public static final String quote(String[] args, String ccl){
		StringBuilder s = new StringBuilder();
		for(int a = 0; a < args.length; a++){
			String arg = args[a];
			int i;
			for(i = 0; i < arg.length(); i++){
				char c = arg.charAt(i);
				if(c == ' ' || c == '\t' || c == '\n' || c == '\'' || ccl != null && ccl.indexOf(c) >= 0)
					break;
			}
			if(i < arg.length() || arg.length() == 0){
				s.append('\'');
				s.append(arg.substring(0, i));
				for(; i < arg.length(); i++){
					char c = arg.charAt(i);
					if(c == '\'')
						s.append('\'');
					s.append(c);
				}
				s.append('\'');
			}else
				s.append(arg);
			if(a < args.length-1)
				s.append(' ');
		}
		return s.toString();
	}

	private static final boolean isspace(char c){
		return c == ' ' || c == '\t' || c == '\n';
	}

	/** Split a quoted string into an array of strings, one per field, with fields separated by unquoted white space */
	public static final String[] unquoted(String s){
		if(s == null)
			s = "";
		ArrayList<String> args = new ArrayList<String>();
		StringBuilder word = new StringBuilder();
		boolean inquote = false;
		int n = s.length();
		for(int j = 0; j < n;){
			char c = s.charAt(j);
			if(isspace(c)){
				j++;
				continue;
			}
			int i;
			for(i = j; i < n && (!isspace(c = s.charAt(i)) || inquote); i++){	// collect word
				if(c == '\''){
					if(i != j)
						word.append(s.substring(j, i));
					j = i+1;
					if(!inquote || j == n || s.charAt(j) != '\'')	// consume the quote?
						inquote = !inquote;
					else
						i++;
				}
			}
			word.append(s.substring(j, i));
			args.add(word.toString());
			word = new StringBuilder();
			j = i;
		}
		if(args.size() == 0)
			args.add("");
		return args.toArray(new String[args.size()]);
	}

	/** Split a string into an array of strings, one per field, where fields are separated by a given set of delimiters */
	public static final String[] getfields(String s, String delim){
		if(s == null)
			s = "";
		StringTokenizer st = new StringTokenizer(s, delim);
		String[] a = new String[st.countTokens()];
		for(int i = 0; i < a.length; i++)
			a[i] = st.nextToken();
		return a;
	}

	/** Convert a utf-8 byte array into a string */
	public static String S(byte[] a){
		try{
			return new String(a, "UTF-8");
		}catch(java.io.UnsupportedEncodingException e){
			throw new RuntimeException("UTF-8 encoding not supported");
		}
	}

	/** Convert a slice of an utf-8 encoded array of bytes into a string */
	public static String S(byte[] a, int o, int l){
		try{
			return new String(a, o, l, "UTF-8");
		}catch(java.io.UnsupportedEncodingException e){
			throw new RuntimeException("UTF-8 encoding not supported");
		}
	}

	/** Convert the contents of a ByteBuffer into a string */
	public static String S(ByteBuffer a){
		try{
			return new String(a.array(), a.arrayOffset()+a.position(), a.remaining(), "UTF-8");
		}catch(java.io.UnsupportedEncodingException e){
			throw new RuntimeException("UTF-8 encoding not supported");
		}
	}

	/** Return the utf-8 encoding of a string */
	public static final byte[] bytes(String s){
		if(s == null)
			return new byte[0];
		try{
			return s.getBytes("UTF-8");
		}catch(java.io.UnsupportedEncodingException e){
			throw new RuntimeException("UTF-8 encoding not supported");	// could just use native encoding
		}
	}

	/** Return the length of a string in its utf-8 encoding */
	public static final int utflen(String s){	// 16-bit unicode only
		int n, l;

		if(s == null)
			return 0;
		n = l = s.length();
		for(int i = 0; i < l; i++){
			int c;
			if((c = s.charAt(i)) > 0x7F){
				n++;
				if(c > 0x7FF)
					n++;
			}
		}
		return n;
	}
}
