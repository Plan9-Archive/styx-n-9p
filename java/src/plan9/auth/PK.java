package plan9.auth;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import plan9.lib.Attrs;

public abstract class PK implements Packable {
	// no constructor, each type has a specific generator in xSK, with appropriate parameters,
	// then apply sktopk. genSK generates a new SK/PK combination but with similar parameters (eg, key length)

	public abstract int nbits();
	public abstract void pack(ByteBuffer b);
	public abstract String toString();
	public abstract boolean verify(PKsig sig, BigInteger m);
	public boolean eq(PK pk2){
		return pk2 != null && (this == pk2 || this.toString().equals(pk2.toString()));
	}
}
