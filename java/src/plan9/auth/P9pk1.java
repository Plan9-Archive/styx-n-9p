package plan9.auth;

/*
 * Plan 9 public key authentication, based on Inferno's public key authentication
 *
 *	Copyright © 2005 Vita Nuova Holdings Limited
 *	Revisions © 2012 Coraid Inc
 *
 * to do
 *	secstore interface
 */

import java.math.BigInteger;
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
import plan9.lib.Msgio;
import plan9.lib.RemoteError;

import plan9.LogFactory;
import plan9.Log;

import static plan9.auth.Pki.*;
import static plan9.auth.Aids.*;
import static plan9.lib.Strings.bytes;

public class P9pk1 {

	static final Log log = LogFactory.logger(P9pk1.class);

	static final Encoding base64 = new Base64();
	static final Encoding base16 = new Base16();

	// alpha and modulus from RFC2409
	static final BigInteger dh_alpha = new BigInteger("2");
	static final BigInteger dh_p = new BigInteger(1, base16.dec("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"));

	public P9pk1(){}

	public String name(){
		return "p9pk1";
	}

	public String init(AuthIO io){
		return null;
	}

	public final String interaction(AuthIO io, Attrs attrs) throws AuthenticationException {
		Authinfo info, hisinfo;
		BigInteger low, r0, alphar0, alphar1, alphar0r1;
		Certificate hiscert;
		Signature alphasig;
		byte[] buf, hispkbuf, alphabuf;
		PK hispk;
		byte[] secret;
		String s, dom;
		Verifier verifier = new Verifier();

		String role = attrs.findattrval("role");
		if(role == null)
			return "role not specified";
		if(!role.equals("client") && !role.equals("server"))
			return "unknown role: "+role;

		dom = attrs.findattrval("dom");
		if(dom == null)
			return "unknown domain";

		info = getauthinfo(io, dom, attrs);	// must extract from attrs, key

		try{
			io.sendmsg("pk v.1");	// version
			s = io.gets();
			String[] flds = Strings.getfields(s, ".");
			if(flds.length < 2 || !flds[0].equals("pk") || !flds[1].equals("v.1"))
				throw new LocalAuthErr("incompatible authentication protocol: "+s);

			// check info here, not above, so that the peer also sees the diagnostic
			checkinfo(info);

			verifier.addkey(info.user);
			verifier.addkey(info.signer);

			low = dh_p.shiftRight(dh_p.bitLength()/4);
			r0 = rand(low, dh_p);
			alphar0 = dh_alpha.modPow(r0, dh_p);
			io.sendmsg(b64(alphar0));

			// send a sequence, at least: mypk, (signer, cert, sig)*
			// public keys must be sent if recipient can't be assumed to know them
			io.sendmsg(info.user.pk.toString());
			io.sendmsg(info.signer.pk.toString());	// needs to be a sequence (Issuer? Subject? Cert Sig)+ in general
			io.sendmsg(info.cert.toString());
			io.sendmsg(info.sig.toString());
			io.sendmsg("");	// end of sequence

			alphar1 = s2big64(io.gets());
			if(dh_p.compareTo(alphar1) <= 0)
				throw new LocalAuthErr("implausible parameter value");
			if(alphar0.compareTo(alphar1) == 0)
				throw new LocalAuthErr("possible replay attack");

			// in general, load a sequence, then interpret it
			// load any keys that arrive into pki? temporary store?
			// check that keys exist for each cert and sig
			// discard any cert that fails validity or signature
			// apply rewrite rules and draw conclusion

			// need: pk, name cert, signature, check that hash of pk matches hash in cert
			// need: spk (known?)

			ArrayList<Object> seq = new ArrayList<Object>();
			for(;;){
				s = io.gets();
				if(s == null || s.equals(""))
					break;
				Attrs a = new Attrs(s);
				if(a.findattr("sig") != null){
					seq.add(new Signature(a));
				}else if(a.findattr("cert") != null){
					seq.add(new Certificate(a));
				}else if(a.findattr("key") != null){
					Key k = new Key(a);
					if(k.secrets.length() > 0)
						verifier.addkey(Pki.parseSK(k).pk());
					else
						verifier.addkey(Pki.parsePK(k));
				}else{
					log.debug("unknown sequence item: %s", s);
				}
			}

			hiscert = verifier.verify(seq);	// summary certificate
			if(hiscert.subject.principal == null)
				hispk = hiscert.issuer.principal.pk;	// was relative name (TO DO: check)
			else
				hispk = hiscert.subject.principal.pk;
			if(hispk == null)
				throw new LocalAuthErr("no public key for subject of remote certificate: "+hiscert.subject);

			// exchange signatures of alphas to check immediate possession of private keys
			alphabuf = bytes(b64(alphar0) + b64(alphar1));
			alphasig = sign(alphabuf, info.user.sk);
			io.sendmsg(alphasig.toString());

			alphasig = new Signature(io.gets());
			alphabuf = bytes(b64(alphar1) + b64(alphar0));
			if(!verify(alphabuf, alphasig, hispk))
				throw new LocalAuthErr("signature did not match pk");

			alphar0r1 = alphar1.modPow(r0, dh_p);
			secret = trim0(alphar0r1.toByteArray());

			io.sendmsg("OK");
//		}catch(InvalidCertificate e){
//			io.senderrmsg("remote: "+e.getMessage());
//			throw e;
//		}catch(InvalidKey e){
//			io.senderrmsg("remote: "+e.getMessage());
//			throw e;
		}catch(LocalAuthErr e){
			io.senderrmsg("remote: "+e.getMessage());
			throw e;
		}catch(RemoteAuthErr e){
			io.senderrmsg("missing your authentication data");	// strange but true
			throw new AuthenticationException(e.getMessage(), e);
		}
		try{
			do{
				s = io.gets();
			}while(!s.equals("OK"));
		}catch(LocalAuthErr e){
			throw new AuthenticationException(e.getMessage(), e);
		}catch(RemoteAuthErr e){
			throw new AuthenticationException("remote: "+e.getMessage(), e);
		}
		// TO DO: add remote pk, spk, names, etc
		io.done(new Attrs(new Attr("secret", (new Base16()).enc(secret)),
			new Attr("suid", "admin"),
			new Attr("cuid", "admin"),
			new Attr("cap", "")));
//		return new AuthResult(new Authinfo(null, hispk, hiscert, info.spk), secret);
		return null;
	}

	static class Authinfo {
		Principal	user;		// current user's public and private keys
		Principal	signer;	// cert's issuer's public key
		Name	issuer;	// issuer name
		Certificate	cert;
		Signature	sig;	// cert's signature

		Authinfo(Principal user, Principal signer, Name issuer, Certificate cert, Signature sig){
			this.user = user; this.signer = signer; this.issuer = issuer; this.cert = cert; this.sig = sig;
		}
	}

	static final void checkinfo(Authinfo info) throws LocalAuthErr {
		if(info == null)
			throw new LocalAuthErr("no authentication information");
		if(info.user == null || info.signer == null || info.issuer == null || !info.issuer.isLocalName() || info.cert == null || info.sig == null)	// could check key details
			throw new LocalAuthErr("invalid authentication information");
	}

	// fetch the output from the prover
	final Authinfo getauthinfo(AuthIO io, String dom, Attrs attrs) throws AuthenticationException {
		// signer's public key, certificate, secret key (use sk.getpk to get public one), alpha, p
		Principal user, signer;
		Certificate cert;
		Signature sig;
		String username;
		Name issuer;

		username = attrs.findattrval("user");
		if(username == null)
			throw new AuthenticationException("user not named for authentication in domain "+dom);
		try{
			Key k = io.findkey(null, String.format("dom=%s proto=p9pk1 user=%s", dom, username));
			SK sk = Pki.parseSK(k);
			user = new Principal(sk.pk(), sk, null);
		}catch(NeedKey e){
			throw new AuthenticationException("can't find key: "+e.getMessage());
		}

		try{
			Key k = io.findkey(null, String.format("dom=%s proto=p9pk1 role=signer", dom));
			PK spk = Pki.parsePK(k);
			signer = new Principal(spk);
		}catch(NeedKey e){
			throw new AuthenticationException("can't find signer's key for domain "+dom);
		}

		issuer = new Name(signer, username);
		try{
			Key k = io.findkey(null, String.format("proto=p9pk1 cert=name issuer=%s subject=%s", issuer, user));
			cert = new Certificate(k.visible);
		}catch(NeedKey e){
			throw new AuthenticationException(String.format("can't find certificate: issuer %s subject %s", issuer, user));
		}

		try{
			Key k = io.findkey(null, String.format("proto=p9pk1 sig signer=%s", signer));	// could add data=hash(cert)
			sig = new Signature(k.visible);
		}catch(NeedKey e){
			throw new AuthenticationException("can't find signature by signer: "+signer);
		}
		return new Authinfo(user, signer, issuer, cert, sig);
	}

	private static int now(){
		return (int)((new Date()).getTime()/1000);
	}

	public static final BigInteger rand(BigInteger p, BigInteger q) throws CryptoError {
		if(p.compareTo(q) > 0){
			BigInteger t = p; p = q; q = t;
		}
		BigInteger diff = q.subtract(p);
		BigInteger two = BigInteger.ONE.add(BigInteger.ONE);
		if(diff.compareTo(two) < 0)
			throw new CryptoError("random number range must be at least two");
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

	public final Signature sign(byte[] a, SK sk) throws CryptoError {
		return Pki.sign(a, "sha1", new Principal(null, sk, null));
	}

	public final boolean verify(byte[] a, Signature s, PK pk) throws CryptoError {
		PKsig sig = s.sig;
		if(!s.alg.equals("rsa-sha1"))
			return false;
		byte[] ah = Aids.sha1(a);
		// TO DO: pkcs1
		return pk.verify(sig, new BigInteger(1, ah));
	}
}
