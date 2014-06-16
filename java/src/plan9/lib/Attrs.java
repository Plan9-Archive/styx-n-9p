package plan9.lib;

//
// attributes
//
// via Limbo version by Vita Nuova, MIT Licence
//
// Java version Copyright © 2012 Coraid Inc

import java.lang.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Collections;

import plan9.lib.Strings;
import plan9.lib.Attr;

public class Attrs implements Iterable<Attr> {

	private ArrayList<Attr> attrs;	// set of attributes

	private Attrs(ArrayList<Attr> attrs){
		this.attrs = attrs;
	}

	public Attrs(String s){	// parse attrs
		String[] fld = Strings.unquoted(s);
		attrs = new ArrayList<Attr>();
		for(String n : fld){
			String v = "";
			int tag = Attr.Name;
			for(int j = 0; j < n.length(); j++){
				if(n.charAt(j) == '='){
					v = n.substring(j+1);
					n = n.substring(0, j);
					tag = Attr.Value;
					break;
				}
			}
			if(n.length() == 0)
				continue;
			if(tag == Attr.Name && n.length() > 1 && n.charAt(n.length()-1) == '?'){
				tag = Attr.Query;
				n = n.substring(0, n.length()-1);
			}
			attrs.add(new Attr(tag, n, v));
		}
		// TO DO: eliminate answered queries
	}

	public Attrs(Attr... t){
		this.attrs = new ArrayList<Attr>(t.length);
		for(Attr a : t)
			this.attrs.add(a);
	}

	public String toString(){
		StringBuilder bs = new StringBuilder(64);
		for(Attr a : attrs){
			if(bs.length() > 0)
				bs.append(' ');
			bs.append(a);
		}
		return bs.toString();
	}

	public Iterator<Attr> iterator(){
		return attrs.iterator();
	}

	public int length(){
		return attrs.size();
	}

	boolean replacement(Attr a){	// does a replace existing attribute?
		for(Attr oa : attrs){
			if(oa.name.equals(a.name)){
				if(a.tag != Attr.Query){ // don't replace value by query
					oa.tag = a.tag;
					oa.val = a.val;
				}
				return true;
			}
		}
		return false;
	}

	public Attrs add(Attr a){
		if(!replacement(a))
			attrs.add(a);
		return this;
	}

	public Attrs add(int pos, Attr a){
		if(!replacement(a))
			attrs.add(pos, a);
		return this;
	}

	public Attr findattr(String name){
		for(Attr a : attrs){
			if(a.tag != Attr.Query && a.name.equals(name))
				return a;
		}
		return null;
	}

	public String findattrval(String name){
		Attr a = findattr(name);
		if(a != null)
			return a.val;
		return null;
	}

	public Attr anyattr(String name){
		for(Attr a : attrs){
			if(a.name.equals(name))
				return a;
		}
		return null;
	}

	public Attrs delattr(String name){
		for(Iterator<Attr> i = attrs.iterator(); i.hasNext();){
			Attr a = i.next();
			if(a.name.equals(name))
				i.remove();
		}
		return this;
	}

	private static final boolean ignored(String s){
		return s == null || s.length() == 0 || s.equals("role") || s.equals("disabled") || s.charAt(0) == ':';
	}

	public boolean matchattr(Attr pat){
		Attr b = findattr(pat.name);
		return b != null && (pat.tag == Attr.Query || b.val.equals(pat.val) || ignored(pat.name));
	}

	public Attrs sorted(){
		Attr proto = null;
		ArrayList<Attr> dup = new ArrayList<Attr>();
		for(Attr a : attrs){
			if(a.name.equals("proto"))
				proto = a;
			else
				dup.add(a);
		}
		Collections.sort(dup);
		if(proto != null)
			dup.add(0, proto);
		return new Attrs(dup);
	}

	public Attrs important(){	// eg, for key matching
		Attrs set = sorted();
		for(Iterator<Attr> i = set.attrs.iterator(); i.hasNext();){
			Attr a = i.next();
				i.remove();
		}
		return set;
	}

	public Attrs copy(){
		ArrayList<Attr> dup = new ArrayList<Attr>();
		for(Attr a : attrs)
			dup.add(a.copy());
		return new Attrs(dup);
	}

	public Attrs setattrs(Attrs newattrs){
		// new attributes
		for(Attr na : newattrs)
			if(anyattr(na.name) == null)
				add(na.copy());

		// new values
		for(Attr oa : attrs){
			Attr na = newattrs.findattr(oa.name);	// won't match queries
			if(na != null){
				oa.tag = Attr.Value;
				oa.val = na.val;
			}
		}
		return this;
	}

	public Attrs setattrs(String s){
		return setattrs(new Attrs(s));
	}

	public Attrs takeattrs(String[] names){
		Attrs taken = new Attrs(new ArrayList<Attr>());
		for(Attr a : attrs){
			for(String name : names){
				if(name.equals(a.name)){
					taken.attrs.add(a.copy());
					break;
				}
			}
		}
		return taken;
	}

	public Attrs publicattrs(){	// TO DO: strange name
		Attrs pubs = new Attrs(new ArrayList<Attr>());
		for(Attr a : attrs){
			if(a.name.charAt(0) != '!' || a.tag == Attr.Query || a.val == null || a.val.equals(""))
				pubs.attrs.add(a.copy());
		}
		return pubs;
	}
}
