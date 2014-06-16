package plan9.auth;

import plan9.lib.Attrs;
import plan9.lib.Base16;
import plan9.lib.Strings;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import java.util.ArrayList;
import java.util.Arrays;

public class PKsig {
	public String alg;	// signature algorithm (eg, "rsa") that determines parameters

	public static class Param {
		String	label;
		byte[]	value;

		public Param(String l, byte[] v){
			this.label = l;
			this.value = v;
		}
	}

	public ArrayList<Param>	sig;	// values in known order

	private static final Base16 base16 = new Base16();

	public PKsig(String alg) {
		this.alg = alg;
		this.sig = new ArrayList<Param>();
	}

	// initialise a signature value for the current algorithm, requiring each given name to have a base16 value in av
	public void init(Attrs av, String... names) throws CryptoError {
		for(String n : names){
			String s = av.findattrval(n);
			if(s == null)
				throw new CryptoError("missing signature attribute: "+n);
			byte v[] = base16.dec(s);
			//if(v == null)
			//	throw new CryptoError("invalid signature attribute value: "+n+": "+s);
			add(n, v);
		}
	}

	public final PKsig add(String n, byte[] v){
		sig.add(new Param(n, Arrays.copyOf(v, v.length)));
		return this;
	}

	public final BigInteger getb(int n) {
		// the exception "can't happen" because we've checked validity when building sig
		if(n < 0 || n >= this.sig.size())
			throw new RuntimeException("invalid PKsig parameter index (internal error)");
		return new BigInteger(1, this.sig.get(n).value);
	}

	// just the values; caller supplies full algorithm
	public String toString(){
		StringBuilder bs = new StringBuilder(64);
		for(Param p : sig){
			if(bs.length() > 0)
				bs.append(' ');
			bs.append(p.label);
			bs.append('=');
			bs.append(base16.enc(p.value));
		}
		return bs.toString();
	}

	public void pack(ByteBuffer b){
		for(Param p : sig)
			b.put(p.value);
	}
}
