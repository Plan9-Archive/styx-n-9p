package plan9.auth;

import java.math.BigInteger;

import java.nio.ByteBuffer;

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

import plan9.Log;
import plan9.LogFactory;

import static plan9.auth.Pki.*;

public class Verifier {

	static final Log log = LogFactory.logger(Verifier.class);

	ArrayList<Principal> keys = new ArrayList<Principal>();

	public final Principal addkey(PK pk){
		try{
			Hash h = Pki.hash("sha1", pk);
			Principal p = keybyhash(h);
			if(p == null){
				p = new Principal(pk, null, h);
				keys.add(p);
			}
			return p;
		}catch(CryptoError e){
			// can't happen, but if it did, just ignore the key
			return null;
		}
	}

	public final Principal addkey(Principal p){
		Principal op = keybyhash(p.pkhash);
		if(op != null)
			return op;
		keys.add(p);
		return p;
	}

	public final Principal keybyhash(Hash h) {
		for(Principal p : keys)
			if(p.eqhash(h))
				return p;
		return null;
	}

	public Certificate verify(ArrayList<Object> seq) throws ValidationFailed {
		ArrayList<Certificate> certs = new ArrayList<Certificate>();
		Name n0 = null;
		Certificate cn = null;
		Tag tag = null;
		long expires = 0;

		for(Object o : seq){
			if(o instanceof Certificate){
				Certificate cert = (Certificate)o;
				if(cert.expires != 0 && cert.expires <= now())
					throw new ValidationFailed("certificate expired: "+cert);
				if(cn != null){
					if(!cn.subject.principal.eq(cert.issuer.principal))
						throw new ValidationFailed(String.format("certificate chain has mismatched principals: subject %s but next issuer %s", cn.subject, cert.issuer));
					if(log.debugging())
						log.debug("subject %s → issuer %s ok", cn.subject, cert.issuer.principal);
				}
				certs.add(cert);
				if(n0 == null)
					n0 = cert.issuer;
				if(cert.expires != 0 && cert.expires < expires)
					expires = cert.expires;
				if(!cert.isNameCert()){
					if(tag != null){
						tag = tag.intersect(cert.tag);
						if(tag.isnone())
							throw new ValidationFailed("certificate chain gives no authority");
					}else
						tag = cert.tag;
				}
				cn = cert;
			}else if(o instanceof Principal){
				Principal p = (Principal)o;
				if(p.pk != null){	// otherwise it's just a hash, and makes no difference
					if(keybyhash(p.pkhash) == null)
						keys.add(p);
				}
			}else if(o instanceof PK){
				addkey((PK)o);
			}else if(o instanceof SK){
				addkey(((SK)o).pk());
			}else if(o instanceof Signature){
				Signature sig = (Signature)o;

				if(cn == null)
					throw new ValidationFailed("invalid proof sequence: signature missing certificate: "+sig);

				Principal p = sig.signer;
				if(p.pk == null){
					// if needed, ought to appear earlier in the sequence
					p = keybyhash(sig.signer.pkhash);
					if(p == null)
						throw new ValidationFailed("missing public key for signer "+sig.signer);
					// could sig.signer.addkey(p.pk);
				}

				// verify signature
				if(!validsig(cn, sig, p))
					throw new ValidationFailed("signature does not match certificate: "+sig.signer);
			}
		}
		if(n0 == null || cn == null)
			throw new ValidationFailed("proof sequence proved nothing");

		if(log.debugging()){
			String s = String.format("Verifier: %s speaks for %s", cn.subject, n0);
			if(tag != null)
				s += " regarding "+tag;
			if(expires != 0)
				s += String.format(" expires %d [%s]", expires, new Date(expires*1000));
			log.debug("%s", s);
		}

		return new Certificate(n0, cn.subject, expires, tag);
	}

	private static int now(){
		return (int)((new Date()).getTime()/1000);
	}

	public final static boolean validsig(Certificate cert, Signature sig, Principal p) throws ValidationFailed {
		try{
			ByteBuffer b = ByteBuffer.allocate(8192);
			cert.pack(b);
			if(!sig.data.alg.equals("sha1"))
				throw new ValidationFailed("unimplemented hash algorithm: "+sig.data.alg);
			byte[] h = Aids.sha1(b.array(), 0, b.position(), null);
			if(log.debugging())
				log.debug("hash cert: %s", Aids.b16(h));
			// TO DO: pkcs1
			if(!sig.signer.pk.verify(sig.sig, new BigInteger(1, h)))
				throw new ValidationFailed("signature verification failed: "+cert);
			return true;
		}catch(Exception e){
			// any error causes validation to fail
			throw new ValidationFailed(e.getMessage());
		}
	}
}
