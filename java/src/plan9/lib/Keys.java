package plan9.lib;

//
// keys
//
// via Limbo version by Vita Nuova, MIT Licence
// Java version Copyright © 2012 Coraid Inc
//
import java.lang.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Collections;

import plan9.lib.Strings;
import plan9.lib.Attr;
import plan9.lib.Attrs;

public class Keys {
	ArrayList<Key> keys;

	public Keys(){
		keys = new ArrayList<Key>();
	}

	public Key findkey(Attrs attrs){
		for(Key k : keys){
			if(k != null && k.matchattrs(attrs))
				return k;
		}
		return null;
	}

	public ArrayList<Key> findkeys(Attrs attrs){
		ArrayList<Key> kl = new ArrayList<Key>();
		for(Key k : keys){
			if(k != null && k.matchattrs(attrs))
				kl.add(k);
		}
		if(kl.size() == 0)
			return null;
		return kl;
	}

	public int delkey(Attrs attrs){
		int nk = 0;
		for(Iterator<Key> i = keys.iterator(); i.hasNext();){
			Key k = i.next();
			if(k != null &&
			   k.matchattrs(attrs)){
				nk++;
				i.remove();
			}
		}
		return nk;
	}

	public void addkey(Key k){
		keys.add(k);	// unclear whether this should eliminate existing matching keys
	}

	public Iterator<Key> iterator(){
		return keys.iterator();
	}
};
