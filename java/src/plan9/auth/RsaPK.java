package plan9.auth;

import java.math.BigInteger;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.nio.*;
import java.nio.channels.*;
import java.io.IOException;
import javax.crypto.Cipher;
import java.io.*;
import java.util.Date;

import java.util.Arrays;
import java.util.ArrayList;

import plan9.lib.Attr;
import plan9.lib.Attrs;
import plan9.lib.Key;
import plan9.lib.Keys;
import plan9.lib.Packer;
import plan9.lib.Strings;
import plan9.lib.Base16;
import plan9.lib.Encoding;
import plan9.lib.Base64;
import plan9.lib.Strings;

import static plan9.auth.Pki.need;
import static plan9.auth.Aids.b64;
import static plan9.auth.Aids.b16;
import static plan9.auth.Aids.s2big16;
import static plan9.auth.Aids.trim0;

public class RsaPK extends PK {
	BigInteger	n;
	BigInteger	ek;

	public RsaPK(BigInteger n, BigInteger ek){
		this.n = n;
		this.ek = ek;
	}
	public RsaPK(Key k) throws InvalidKey {
		// ignore size=, since we'll compute it
		this(s2big16(need(k, "n")), s2big16(need(k, "ek")));
	}
	public final int nbits(){
		return n.bitLength();
	}
	public final void pack(ByteBuffer b){
		b.put(trim0(this.n.toByteArray()));
		b.put(trim0(this.ek.toByteArray()));
	}
	public String toString(){
		return String.format("size=%d ek=%s n=%s", n.bitLength(), b16(ek), b16(n));
	}

	public boolean verify(PKsig sig, BigInteger m){
		return rsaencrypt(sig.getb(0)).equals(m);
	}

	// extensions
	public final BigInteger  rsaencrypt(BigInteger data){
System.out.format("ek: %s%n", this.ek);
System.out.format("n: %s%n", this.n);
System.out.format("data: %s%n", data);
System.out.format("data.modpow: %s%n", data.modPow(this.ek, this.n));
		return data.modPow(this.ek, this.n);
	}

	// conversion between RSAPublicKey and RsaPK
	public RsaPK(RSAPublicKey pk){
		this.n = pk.getModulus();
		this.ek = pk.getPublicExponent();
	}
	public final RSAPublicKey getRSAPublicKey() throws InvalidKey {
		try{
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
			return (RSAPublicKey)keyfactory.generatePublic(new RSAPublicKeySpec(n, ek));
		}catch(InvalidKeySpecException e){
			throw new InvalidKey("bad key spec: "+e.getMessage());
		}catch(NoSuchAlgorithmException e){
			throw new InvalidKey("RSA not implemented: "+e.getMessage());
		}
	}
}
