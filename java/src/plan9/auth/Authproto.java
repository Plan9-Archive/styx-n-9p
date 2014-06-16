package plan9.auth;

import plan9.lib.Attrs;
import plan9.lib.Key;

public interface Authproto {
	String	name();
	String	init(AuthIO io);
	String	interaction(AuthIO io, Attrs attrs) throws AuthenticationException, CryptoError;
	String	keycheck(Key k);
};
