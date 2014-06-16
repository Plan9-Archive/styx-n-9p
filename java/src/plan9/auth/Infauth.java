package plan9.auth;

/*
 * Inferno public key authentication
 *
 *	Copyright © 2005 Vita Nuova Holdings Limited
 *
 * to do
 *	attr=val keys
 *	secstore interface
 *	Auth.auth
 */

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

import static plan9.lib.Strings.bytes;
import plan9.lib.Strings;
import plan9.lib.Msgio;
import plan9.lib.RemoteError;

//java.security.interfaces.RSAKey, RSAPrivateCrtKey, RSAPrivateKey, RSAPublicKey
// use instanceof applied to java.security.PublicKey

//java.security.spec
//	use with java.security.KeyFactory and java.security.AlgorithmParameters
//	RSAKeyGenParameterSpec(modulus, pubexp, privexp, primeP, primeQ, primeExpP, primeExpQ, crtCoeff)
//		getCrtCoefficient, getPrimeExponentP, getPrimeExponentQ, getPrimeP, getPrimeQ, getPublicExponent
//	RSAPrivateKeySpec(modulus, privateexp)
//		getModulus, getPrivateExponent
//	RSAPublicKeySpec(modulus, publicexp)
//		getModulus, getPublicExponent

import static plan9.auth.Aids.*;

public class Infauth {

	final static int Maxmsg = 4096;

	static KeyFactory keyfactory;

	public Infauth() throws NoSuchAlgorithmException {
		if(keyfactory == null)
			keyfactory = KeyFactory.getInstance("RSA");
	}

	public static class InfPublicKey {
		public PublicKey	pk;
		public String	owner;

		public InfPublicKey(PublicKey pk, String owner){
			this.pk = pk; this.owner = owner;
		}
		public InfPublicKey(String s) throws InvalidKey {
			if(s == null)
				throw new InvalidKey("missing public key");
			String[] a = Strings.getfields(s, "\n");
			if(a.length < 4)
				throw new InvalidKey("bad public key syntax");
			if(!a[0].equals("rsa"))
				throw new InvalidKey("unknown key algorithm: "+a[0]);
			BigInteger modulus = s2big64(a[2]);
			BigInteger publicexp = s2big64(a[3]);
			try{
				this.pk = keyfactory.generatePublic(new RSAPublicKeySpec(modulus, publicexp));
			}catch(InvalidKeySpecException e){
				throw new InvalidKey("bad key spec: "+e.getMessage(), e);
			}
			this.owner = a[1];
		}
		public String text(){
			RSAPublicKey pk = (RSAPublicKey)this.pk;
			return "rsa\n"+this.owner+"\n"+b64(pk.getModulus())+"\n"+b64(pk.getPublicExponent())+"\n";
		}
		public String toString(){
			return pk.toString()+"\nowner="+owner;
		}
	}

	public static class InfPrivateKey {
		PrivateKey	sk;
		public String	owner;

		public InfPrivateKey(PrivateKey sk, String owner){
			this.sk = sk; this.owner = owner;
		}
		public InfPrivateKey(String s) throws InvalidKey {
			if(s == null)
				throw new InvalidKey("missing private key");
			String[] a = Strings.getfields(s, "\n");
			if(a.length < 10)
				throw new InvalidKey("bad private key syntax");
			if(!a[0].equals("rsa"))
				throw new InvalidKey("unknown key algorithm: "+a[0]);
			BigInteger n = s2big64(a[2]);
			BigInteger e = s2big64(a[3]);
			BigInteger dk = s2big64(a[4]);
			BigInteger p = s2big64(a[5]);
			BigInteger q = s2big64(a[6]);
			BigInteger kp = s2big64(a[7]);
			BigInteger kq = s2big64(a[8]);
			BigInteger c12 = s2big64(a[9]);
			// mind your p's and q's: libsec's p is java's q!  (Java follows PKCS#1 in reversing their roles)
			// if using Java's RSA implementation directly, reverse p and q, and kp and kq
			// we can't use it here because it imposes PKCS#1, so we do the calculation ourselves
			try{
				this.sk = keyfactory.generatePrivate(new RSAPrivateCrtKeySpec(n, e, dk, p, q, kp, kq, c12));
			}catch(InvalidKeySpecException ex){
				throw new InvalidKey("bad key spec: "+ex.getMessage(), e);
			}
			this.owner = a[1];
		}
		public InfPublicKey getpk() throws InvalidKey {
			RSAPrivateCrtKey rsk = (RSAPrivateCrtKey)this.sk;
			try{
				PublicKey pk = keyfactory.generatePublic(new RSAPublicKeySpec(rsk.getModulus(), rsk.getPublicExponent()));
				return new InfPublicKey(pk, this.owner);
			}catch(InvalidKeySpecException e){
				throw new InvalidKey("bad key spec: "+e.getMessage(), e);
			}
		}
		public String text(){
			RSAPrivateCrtKey sk = (RSAPrivateCrtKey)this.sk;
			return "rsa\n"+
				b64(sk.getModulus())+"\n"+
				b64(sk.getPublicExponent())+"\n"+
				b64(sk.getPrivateExponent())+"\n"+
				b64(sk.getPrimeP())+"\n"+
				b64(sk.getPrimeQ())+"\n"+
				b64(sk.getPrimeExponentP())+"\n"+
				b64(sk.getPrimeExponentQ())+"\n"+
				b64(sk.getCrtCoefficient())+"\n";
		}
		public String toString(){
			return sk.toString()+"\nowner="+owner;
		}
	}

	public static class Authinfo {
		public InfPrivateKey	mysk;
		public InfPublicKey	mypk;
		public Certificate	cert;	// signature of my public key
		public InfPublicKey	spk;	// signer's public key
		public BigInteger	alpha;	// diffie-hellman parameters
		public BigInteger	p;

		public Authinfo(InfPrivateKey sk, InfPublicKey pk, Certificate cert, InfPublicKey spk, BigInteger alpha, BigInteger p){
			this.mysk = sk; this.mypk = pk; this.cert = cert; this.spk = spk; this.alpha = alpha; this.p = p;
		}
	}
	public final Authinfo readauthinfo(ByteChannel fd) throws Exception {
		// signer's public key, certificate, secret key (use sk.getpk to get public one), alpha, p
		InfPublicKey spk;
		Certificate cert;
		InfPrivateKey mysk;
		BigInteger alpha, p;
		Msgio io;

		io = new Msgio(fd);
		spk = new InfPublicKey(io.gets());
		cert = new Certificate(io.gets());
		mysk = new InfPrivateKey(io.gets());
		alpha = s2big64(io.gets());
		p = s2big64(io.gets());
		return new Authinfo(mysk, mysk.getpk(), cert, spk, alpha, p);
	}

	public static class Certificate {
		public String	sa;	// signature algorithm
		public String	ha;	// hash algorithm
		public String	signer;	// name of signer
		public int		exp;	// expiration date (seconds from Epoch, 0=never)
		BigInteger	rsa;	// only RSA signatures supported

		public Certificate(String sa, String ha, String signer, int exp, BigInteger rsa){
			this.sa = sa; this.ha = ha; this.signer = signer; this.exp = exp; this.rsa = rsa;
		}
		public Certificate(String s) throws InvalidCertificate {
			if(s == null)
				throw new InvalidCertificate("missing certificate");
			String[] a = Strings.getfields(s, "\n");
			if(a.length < 5)
				throw new InvalidCertificate("bad certificate syntax"+":"+a.length);
			this.sa = a[0];
			this.ha = a[1];
			this.signer = a[2];
			this.exp = Integer.parseInt(a[3]);
			this.rsa = s2big64(a[4]);
		}
		public final String text(){
			return this.sa+"\n"+this.ha+"\n"+this.signer+"\n"+this.exp+"\n"+b64(this.rsa)+"\n";
		}
	}

	public static class AuthResult {
		public Authinfo	info;
		public byte[]	secret;

		AuthResult(Authinfo info, byte[] secret){
			this.info = info; this.secret = secret;
		}
	}

	public final AuthResult basicauth(ByteChannel fd, Authinfo info) throws AuthenticationException {
		BigInteger low, r0, alphar0, alphar1, alphar0r1;
		Certificate hiscert, alphacert;
		Msgio io = new Msgio(fd);
		byte[] buf, hispkbuf, alphabuf;
		InfPublicKey hispk;
		byte[] secret;
		int vers;

		try{
			io.sendmsg("1");	// version
			buf = io.getmsg();
			vers = Integer.parseInt(Strings.S(buf));
			if(vers != 1 || buf.length > 4)
				throw new LocalAuthErr("incompatible authentication protocol");
			if(info == null)
				throw new LocalAuthErr("no authentication information");
			if(info.p == null)
				throw new LocalAuthErr("missing diffie hellman mod");
			if(info.alpha == null)
				throw new LocalAuthErr("missing diffie hellman base");
			if(info.mysk == null || info.mypk == null || info.cert == null || info.spk == null)	// could check key details
				throw new LocalAuthErr("invalid authentication information");
			if(info.p.compareTo(BigInteger.ZERO) <= 0)
				throw new LocalAuthErr("-ve modulus");

			low = info.p.shiftRight(info.p.bitLength()/4);
			r0 = rand(low, info.p);
			alphar0 = info.alpha.modPow(r0, info.p);
			io.sendmsg(b64(alphar0));
			io.sendmsg(info.cert.text());
			io.sendmsg(info.mypk.text());

			alphar1 = s2big64(io.gets());
			if(info.p.compareTo(alphar1) <= 0)
				throw new LocalAuthErr("implausible parameter value");
			if(alphar0.compareTo(alphar1) == 0)
				throw new LocalAuthErr("possible replay attack");
			hiscert = new Certificate(io.gets());
			hispkbuf = io.getmsg();
			hispk = new InfPublicKey(Strings.S(hispkbuf));
			if(!verify(info.spk, hiscert, hispkbuf))
				throw new LocalAuthErr("pk doesn't match certificate");
			if(hiscert.exp != 0 && hiscert.exp <= now())
				throw new LocalAuthErr("certificate expired");

			alphabuf = bytes(b64(alphar0) + b64(alphar1));
			alphacert = sign(info.mysk, 0, alphabuf);
			io.sendmsg(alphacert.text());
			alphacert = new Certificate(io.gets());
			alphabuf = bytes(b64(alphar1) + b64(alphar0));
			if(!verify(hispk, alphacert, alphabuf))
				throw new LocalAuthErr("signature did not match pk");

			alphar0r1 = alphar1.modPow(r0, info.p);
			secret = trim0(alphar0r1.toByteArray());

			io.sendmsg("OK");
		}catch(ClosedByInterruptException e){
			throw new LocalAuthErr("interrupted by time-out", e);
		}catch(IOException e){
			throw new LocalAuthErr("i/o error: "+e.getMessage());	// could distinguish a few cases
		}catch(InvalidCertificate e){
			io.senderrmsg("remote: "+e.getMessage());
			throw e;
		}catch(InvalidKey e){
			io.senderrmsg("remote: "+e.getMessage());
			throw e;
		}catch(NoSuchAlgorithmException e){
			String msg =  "unsupported algorithm: "+e.getMessage();
			io.senderrmsg("remote: "+msg);
			throw new AuthenticationException(msg);
		}catch(LocalAuthErr e){
			io.senderrmsg("remote: "+e.getMessage());
			throw e;
		}catch(RemoteError e){
			io.senderrmsg("missing your authentication data");	// strange but true
			throw new AuthenticationException(e.getMessage());
		}
		try{
			String s;
			do{
				s = io.gets();
			}while(!s.equals("OK"));
		}catch(ClosedByInterruptException e){
			throw new AuthenticationException("interrupted by time-out", e);
		}catch(IOException e){
			throw new AuthenticationException("i/o error: "+e.getMessage());
		}catch(RemoteError e){
			throw new AuthenticationException("remote: "+e.getMessage());
		}
		return new AuthResult(new Authinfo(null, hispk, hiscert, info.spk, info.alpha, info.p), secret);
	}

	private static int now(){
		return (int)((new Date()).getTime()/1000);
	}

	public static final BigInteger rand(BigInteger p, BigInteger q) throws IllegalArgumentException  {
		if(p.compareTo(q) > 0){
			BigInteger t = p; p = q; q = t;
		}
		BigInteger diff = q.subtract(p);
		BigInteger two = BigInteger.ONE.add(BigInteger.ONE);
		if(diff.compareTo(two) < 0)
			throw new IllegalArgumentException("range must be at least two");
		int l = diff.bitLength();
		BigInteger t = BigInteger.ONE.shiftLeft(l);
		l = (l + 7) & ~7;	// nearest byte
		BigInteger slop = t.mod(diff);
		BigInteger r;
		do{
			byte[] buf = new byte[l];
			Aids.memrandom(buf, 0, l);
			r = new BigInteger(1, buf);
		}while(r.compareTo(slop) < 0);
		return r.mod(diff).add(p);
	}

	public final void setlinecrypt(ByteChannel fd, String role, String[] algs) throws IOException {
		String alg;
		Msgio io;

		io = new Msgio(fd);
		if(role.equals("client")){
			if(algs != null && algs.length > 0)
				alg = algs[0];
			else
				alg = "none";	// alg = "md5/rc4_256";	// no idea how to make use of SSL without its handshake
			io.sendmsg(alg);
		}else if(role.equals("server")){
			try{
				alg = io.gets();
			}catch(RemoteError e){
				throw new IOException("remote: "+e.getMessage(), e);	// can't happen
			}
			if(!alg.equals("none"))
				throw new IOException("unsupported algorithm: "+alg);
		}else
			throw new IOException("invalid role: "+role);
	}

	public final AuthResult auth(ByteChannel fd, String role, Authinfo info, String[] algs) throws AuthenticationException, IOException {
		AuthResult a;
		a = basicauth(fd, info);
		setlinecrypt(fd, role, algs);
		return a;
	}

	private static final BigInteger  rsaencrypt(RSAPublicKey pk, BigInteger data){
		return data.modPow(pk.getPublicExponent(), pk.getModulus());
	}
	public final Certificate sign(InfPrivateKey sk, int exp, byte a[]) throws NoSuchAlgorithmException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		BigInteger sig, digest;
		sha1.update(a);
		// add signer's name and expiration to hash
		sha1.update(bytes(sk.owner+" "+exp));	// "%s %d"
		digest = new BigInteger(1, sha1.digest());
		sig = rsadecrypt(digest, sk.sk);
		return new Certificate("rsa", "sha1", sk.owner, exp, sig);
	}
	public final boolean verify(InfPublicKey pk, Certificate c, byte a[]) throws NoSuchAlgorithmException {
		if(!c.sa.equals("rsa") || !c.ha.equals("sha1") && !c.ha.equals("sha"))
			return false;
		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		sha1.update(a);
		sha1.update(bytes(c.signer+" "+c.exp));
		return rsaverify(new BigInteger(1, sha1.digest()), c.rsa, (RSAPublicKey)pk.pk);
	}
	public static final BigInteger rsadecrypt(BigInteger n, PrivateKey rsa1){
		RSAPrivateCrtKey rsa = (RSAPrivateCrtKey)rsa1;
		BigInteger p, q, v1, v2;
		p = rsa.getPrimeP();
		v1 = n.mod(p);
		q = rsa.getPrimeQ();
		v2 = n.mod(q);
		v1 = v1.modPow(rsa.getPrimeExponentP(), p);
		v2 = v2.modPow(rsa.getPrimeExponentQ(), q);
		// out = v1 + p*((v2-v1)*c2 mod q)
		return v2.subtract(v1).multiply(rsa.getCrtCoefficient()).mod(q).multiply(p).add(v1);
	}
	public static final boolean rsaverify(BigInteger m, BigInteger sig, RSAPublicKey key){
		return rsaencrypt(key, sig).equals(m);
	}
}
