package plan9.auth;

import java.util.ArrayList;
import java.util.Iterator;

import plan9.lib.Key;

// Copyright © 2012 Coraid Inc
// based on LGPL code in Inferno, now MIT licence

/**
 * GetKey stores a set of Factotum keys, in parsed form.
 * It offers operations to find a key or keys matching a template,
 * or replace the first key that matches a template.
 * A "template" has a similar syntax to a key, but instead of just attribute=value or plain attribute names,
 * which must match exactly, it allows a trailing "?" (eg, user? !password?) to represent a key
 * where the attribute must appear in the key to match, but may have any value.
 * See Plan 9's {@link "http://plan9.bell-labs.com/magic/man2html/4/factotum" "factotum(4)"} for details.
 */
public interface GetKey {

	/** Return the first key that matches the given template; return null if no key matches */
	Key	getkey(String template);

	/** Return the set of keys that matches the given template; return null if no key matches */
	ArrayList<Key> getkeys(String template);

	/**
	 * Return a new key to replace k, which proved unable to authenticate (for the given reason), 
	 * and which should be removed from the key store.
	 * The new key should match the given template.
	 * Return null if no such key is found.
	 */
	Key	replacekey(Key k, String why, String newtemplate);
};
