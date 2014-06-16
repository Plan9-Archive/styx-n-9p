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

import plan9.LogFactory;
import plan9.Log;

import static plan9.auth.Pki.need;
import static plan9.auth.Aids.b64;
import static plan9.auth.Aids.b16;
import static plan9.auth.Aids.s2big64;
import static plan9.auth.Aids.s2big16;
import static plan9.auth.Aids.trim0;

public class RsaSK implements SK {

	static final Log log = LogFactory.logger(RsaSK.class);

	BigInteger n;
	BigInteger ek;
	BigInteger dk;
	BigInteger p;
	BigInteger q;
	BigInteger kp;
	BigInteger kq;
	BigInteger c12;

	public RsaSK(int length) throws CryptoError {
		try{
			// can't easily make kpg static because key-pair lengths might vary
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(length);
			KeyPair kp = kpg.generateKeyPair();
			extract((RSAPrivateKey)kp.getPrivate());
		}catch(NoSuchAlgorithmException e){
			throw new CryptoError("no KeyPairGenerator for RSA: "+e.getMessage());
		}catch(InvalidParameterException e){
			throw new CryptoError("unsupported length for RSA: "+length);
		}
	}
	public RsaSK(RSAPrivateKey sk){
		extract(sk);
	}
	public RsaSK(Key k) throws InvalidKey {
		n = s2big16(need(k, "n"));
		ek = s2big16(need(k, "ek"));
		dk = s2big16(need(k, "!dk"));
		p = s2big16(need(k, "!p"));
		q = s2big16(need(k, "!q"));
		kp = s2big16(need(k, "!kp"));
		kq = s2big16(need(k, "!kq"));
		c12 = s2big16(need(k, "!c2"));
	}
	public String toString(){
		// size ek !dk n !p !q !kp !kq !c2
		return String.format("size=%d ek=%s !dk=%s n=%s !p=%s !q=%s !kp=%s !kq=%s !c2=%s",
			this.n.bitLength(), b16(this.ek), b16(this.dk),
			b16(this.n), b16(this.p), b16(this.q),
			b16(this.kp), b16(this.kq), b16(this.c12));
	}

	public final PKsig sign(BigInteger digest){
		BigInteger val = rsadecrypt(digest);
System.out.format("digest=%s%nval=%s%n", digest, val);
System.out.format("val'=%s%n", b16(val.toByteArray()));
		PKsig sig = new PKsig("rsa");
		sig.add("val", trim0(val.toByteArray()));
		return sig;
	}

	public final PK pk(){
		return new RsaPK(n, ek);
	}

	// extra operation not in SK/PK
	public final BigInteger rsadecrypt(BigInteger m){
		BigInteger v1, v2;
		v1 = m.mod(p);
		v2 = m.mod(q);
		v1 = v1.modPow(kp, p);
		v2 = v2.modPow(kq, q);
		// out = v1 + p*((v2-v1)*c2 mod q)
		return v2.subtract(v1).multiply(c12).mod(q).multiply(p).add(v1);
	}

	// for reference: unused
	protected RSAPrivateKey cvt() throws InvalidKey {
		// we can't actually use Java's operations here because it imposes PKCS#1, so we do the calculation ourselves
		try{
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
			RSAPrivateKey jsk = (RSAPrivateKey)keyfactory.generatePrivate(new RSAPrivateCrtKeySpec(n, ek, dk, q, p, kq, kp, c12));
			if(log.debugging())
				log.debug("java sk = %s", jsk);
			return jsk;
		}catch(InvalidKeySpecException ex){
			throw new InvalidKey("bad key spec: "+ex.getMessage());
		}catch(NoSuchAlgorithmException e){
			throw new InvalidKey("RSA not implemented: "+e.getMessage());
		}
	}

	// extract the components from a Java-generated key
	private void extract(RSAPrivateKey sk){
		// mind your p's and q's: libsec's p is java's q!  (Java follows PKCS#1 in reversing their roles)
		// to use Java's RSA implementation directly, we reverse p and q, and kp and kq
		// apparently we can safely do these casts
		RSAPrivateCrtKey ck = (RSAPrivateCrtKey)sk;
		n = ck.getModulus();
		ek = ck.getPublicExponent();
		dk = ck.getPrivateExponent();
		p = ck.getPrimeQ();
		q = ck.getPrimeP();
		kp = ck.getPrimeExponentQ();
		kq = ck.getPrimeExponentP();
		c12 = ck.getCrtCoefficient();
	}
}
