package plan9.auth;

import java.math.BigInteger;

public interface SK {
	// one generalised constructor in Pki (genSK)
	// each type has a specific generator in Pki, with appropriate parameters
	// we're only interested in signatures, and don't offer encrypt/decrypt operations here,
	// but a given key type might offer them

	public PK	pk();
	public PKsig	sign(BigInteger m);
}
