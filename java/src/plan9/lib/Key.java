package plan9.lib;

//
// keys
//
// via Limbo version by Vita Nuova, MIT Licence
//
// Java version Copyright © 2012 Coraid Inc

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Collections;

import plan9.lib.Strings;
import plan9.lib.Attr;
import plan9.lib.Attrs;

/**
 * Keys are parsed into a type that stores the visible and secret attributes (the ones starting with "!") separately.
 */
public class Key {
	public Attrs	visible;	// public knowledge
	public Attrs	secrets;	// something to hide

	public Key(Attrs attrs){	// mixture of visible and secret
		visible = new Attrs();
		secrets = new Attrs();
		Attr proto = null;
		for(Attr a : attrs){
			if(proto == null && a.name.equals("proto"))
				proto = a;
			else if(a.isPublic())
				visible.add(a);
			else
				secrets.add(a);
		}
		if(proto != null)
			visible.add(0, proto);	// push proto to the front
	}

	/** Parse the string s into the Key representation */
	public Key(String s){
		this(new Attrs(s));
	}

	/** Return the value of the first instance of name=value in the key */
	public String findattrval(String name){
		if(name.length() == 0)
			return null;
		if(name.charAt(0) == '!')
			return secrets.findattrval(name);
		return visible.findattrval(name);
	}

	/** Return a string that represents the key in textual form, but stripping the values from the secret attributes */
	public String toString(){
		StringBuilder bs = new StringBuilder(64);
		bs.append(visible);
		boolean sp = bs.length() != 0;
		for(Attr a : secrets){
			if(sp)
				bs.append(' ');
			bs.append(a.name);
			bs.append('?');
		}
		return bs.toString();
	}

	/** Return a string that represents the key in textual form, including the values of secret attributes. NOT TO BE USED LIGHTLY */
	public String fullText(){
		StringBuilder bs = new StringBuilder(64);
		bs.append(visible);
		if(bs.length() != 0 && secrets != null)
			bs.append(' ');
		return bs.append(secrets).toString();
	}

	/** Return true iff the key matches the given set of attributes */
	public boolean matchattrs(Attrs attrs){
		for(Attr a : attrs){
			if(!visible.matchattr(a) && !secrets.matchattr(a))
				return false;
		}
		return true;
	}

	/** Given a set of attribute names that must have values, return a string that lists the missing values in the form of a key template */
	public String requires(String[] names){
		StringBuilder bs = new StringBuilder(64);
		for(String name : names){
			if(name == null || name.length() == 0)
				continue;
			if(name.charAt(0) == '!'){
				if(secrets.findattr(name) != null)
					continue;
			}else if(visible.findattr(name) != null)
				continue;
			if(bs.length() > 0)
				bs.append(' ');
			bs.append(name);
		}
		if(bs.length() > 0)
			return bs.toString();
		return null;
	}
}
