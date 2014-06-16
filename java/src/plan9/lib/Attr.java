package plan9.lib;

//
// client interface to factotum
//
// via Limbo version by Vita Nuova, MIT Licence
//
// Java version Copyright © 2012 Coraid Inc

import java.lang.*;
import plan9.lib.Strings;

//
// attribute
//	Name:	attr
//	Value:	attr=value
//	Query:	attr?
// attr starting ! is secret
//

public class Attr implements Comparable<Attr> {

	public static final int Name = 0;
	public static final int Value = 1;
	public static final int Query = 2;

	public int tag;
	public String name;
	public String val;

	public Attr(int tag, String name, String val){
		this.tag = tag;
		this.name = name;
		this.val = val;
	}
	public Attr(String name, String val){
		this.tag = Value;
		this.name = name;
		this.val = val == null? "": val;
	}
	public Attr(String name){
		this.tag = Name;
		this.name = name;
		this.val = null;
	}

	public Attr copy(){
		return new Attr(tag, name, val);
	}
	public String toString(){
		switch(tag){
		case Name:	return name;
		case Value:	return Strings.quote(name)+"="+Strings.quote(val);
		case Query:	return Strings.quote(name)+"?";
		default:	return "??";
		}
	}
	public boolean isSecret(){
		return name.charAt(0) == '!';
	}
	public boolean isPublic(){
		return !isSecret();
	}

	// public, but not yet sure whether to publish them
	public boolean equals(Object o){
		if(o == null || !(o instanceof Attr))
			return false;
		if(o == this)
			return true;
		Attr a = (Attr)o;
		if(!(a.tag == tag && a.name.equals(name)))
			return false;
		if(val == null)
			return a.val == null;
		if(a.val == null)
			return val == null;
		return a.val.equals(val);
	}
	public int hashCode(){
		if(val == null)
			return tag ^ name.hashCode();
		return tag ^ name.hashCode() ^ val.hashCode();
	}
	public int compareTo(Attr a){
		// tag doesn't matter
		if(!name.equals(a.name))
			return name.compareTo(a.name);
		if(val == null)
			return a.val == null? 0: 1;
		if(a.val == null)
			return 1;
		return val.compareTo(a.val);
	}
}
