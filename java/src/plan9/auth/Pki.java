package plan9.auth;

// public/private key pairs and related data types

// - certificates and signatures refer to keys by the hash of their public keys
//	(no point in indirection by name, because sig must freeze value of issuer and subject key)
// - could allow a name tag that's not part of the signature, to allow auth protocols to refer to it
// - need only components for basic exchange

// - need a shortform text, for diagnostics

import java.lang.Integer;

import java.math.BigInteger;

import java.util.Arrays;
import java.util.ArrayList;

import java.nio.ByteBuffer;

import plan9.lib.Attr;
import plan9.lib.Attrs;
import plan9.lib.Base16;
import plan9.lib.Base64;
import plan9.lib.Key;
import plan9.lib.Strings;

import static plan9.auth.Aids.b16;
import static plan9.auth.Aids.b64;

public class Pki {

	static final Base16 base16 = new Base16();
	static final Base64 base64 = new Base64();

	public static class Hash implements Packable {
		public	String	alg;
		public	byte[]	value;

		public Hash(String alg, byte[] value){
			this.alg = alg;
			this.value = Arrays.copyOf(value, value.length);
		}

		public	Hash(String s) throws CryptoError {
			String[] flds = Strings.getfields(s, ":");
			if(flds.length == 1){
				this.alg = "sha1";
				this.value = base16.dec(flds[0]);
			}else if(flds.length == 2){
				this.alg = flds[0];
				this.value = base16.dec(flds[1]);
			}else
				throw new CryptoError("invalid hash value");
		}

		public	boolean	eq(Hash h2){
			return this.alg.equals(h2.alg) && Arrays.equals(this.value, h2.value);
		}

		public	void		pack(ByteBuffer b){
			b.put(value);
		}

		public	String	toString(){
			if(alg.equals("sha1"))
				return base16.enc(value);
			return alg+":"+base16.enc(value);
		}
	}

	// authorisation or name certificate
	// authorisation certificate has tag and issuer is key
	// name certificate has no tag (or it's ignored) and issuer is key+name
	public static class Certificate implements Packable {
		public Name	issuer;
		public Name	subject;
		public long	expires;	// usual epoch time, 0 means never
		public Tag	tag;		// null for name certificate ("*" assumed)

		Certificate(){
			this.issuer = null;
			this.subject = null;
			this.tag = null;
			this.expires = 0;
		}

		public Certificate(Name issuer, Name subject, long expires, Tag tag){
			this.issuer = issuer;
			this.subject = subject;
			this.expires = expires;
			this.tag = tag;
		}

		public Certificate(String s) throws CryptoError {
			this(new Attrs(s));
		}

		public Certificate(Attrs av) throws CryptoError {
			String v;
			this.issuer = new Name(need(av, "issuer"));
			this.subject = new Name(need(av, "subject"));
			v = av.findattrval("expires");
			if(v != null){
				try{
					expires = Integer.parseInt(v);
				}catch(NumberFormatException e){
					throw new CryptoError("invalid 'expires' value");
				}
			}else
				expires = 0;
			v = av.findattrval("tag");
			if(v != null)
				this.tag = new Tag(v);
			else
				this.tag = null;
			if(this.issuer.hasNames()){
				if(this.tag != null && !this.tag.isall())
					throw new CryptoError("name certificate should not contain tag");
				// TO DO: check: should there be only one?
				//if(!this.issuer.hasNames())
				//	throw new CryptoError("name certificate needs issuer name");
			}
		}

		public Principal	principal() {	// issuing principal (key)
			return this.issuer.principal;
		}

		public boolean isNameCert(){
			return this.issuer.hasNames();
		}

		final String expiry(){
			if(expires != 0)
				return String.format("expires=%d", expires);
			return "";
		}

		public final void pack(ByteBuffer b){
			// put together canonical form for signature
			issuer.pack(b);
			subject.pack(b);
			b.put(Strings.bytes(Long.toString(expires)));
			if(tag != null)
				tag.pack(b);
		}

		public String toString(){
			if(isNameCert())
				return String.format("cert=name issuer=%s subject=%s %s",
					Strings.quote(issuer.toString()), Strings.quote(subject.toString()), expiry());
			String s = String.format("cert=auth issuer=%s subject=%s %s",
				Strings.quote(issuer.toString()), Strings.quote(subject.toString()), expiry());
			if(tag != null)
				s += " "+tag.toString();
			return s;
		}
	}

	// a principal is a public key, or a hash of a public key
	// given a private key, we extract the public key components
	// there is always a hash, and sometimes a public key
	public static class Principal implements Packable {
		public	PK	pk;	// public key, once known
		public	SK	sk;	// secret (private) key
		public	Hash	pkhash;	// hash of public key, always known

		public Principal(PK pk, SK sk, Hash h) throws CryptoError {
			if(pk == null && sk != null)
				pk = sk.pk();
			if(h == null && pk != null)
				h = hash("sha1", pk);
			this.pk = pk;
			this.sk = sk;
			this.pkhash = h;
		}

		public Principal(PK pk) throws CryptoError {
			this(pk, null, null);
		}

		public Principal(String s) throws CryptoError {
			this(null, null, new Hash(s));
		}

		public boolean eq(Principal p2){
			if(this == p2)
				return true;
			if(pkhash != null && p2.pkhash != null)
				return pkhash.eq(p2.pkhash);
			return pk.eq(p2.pk);
		}

		public boolean eqhash(Hash h){
			return h.eq(pkhash);
		}

		// add the public key if it's missing
		public void addkey(PK pk){
			if(this.pk == null)
				this.pk = pk;
		}

		// use Principal.pk.pack() to pack unhashed version (if available)
		// hashed version is always used in certificates (unlike SPKI, which allows full key to be nested)
		public void pack(ByteBuffer b){
			pkhash.pack(b);
		}

		// use Principal.pk.toString() to get unhashed version
		public String toString(){
			return pkhash.toString();
		}

	}

	static final boolean samenames(ArrayList<String> a1, ArrayList<String> a2){
		if(a1 == null)
			return a2 == null;
		if(a1.size() != a2.size())
			return false;
		for(int i = a1.size(); --i >= 0;)
			if(!a1.get(i).equals(a2.get(i)))
				return false;
		return true;
	}

	// Name = Principal | Principal String+
	// both components cannot be null or empty
	// Principal is always a hash of the public key
	public static class Name implements Packable {
		public	Principal	principal;
		public	ArrayList<String>	idents;

		public Name(Principal p){
			this.principal = p;
			this.idents = new ArrayList<String>();
		}
		public Name(Principal p, ArrayList<String> idents){
			this(p);
			for(String s : idents)
				this.idents.add(s);
		}
		public Name(Principal p, String... idents){
			this(p);
			for(String s : idents)
				add(s);
		}
		public Name(String s) throws CryptoError {
			this.principal = null;
			this.idents = new ArrayList<String>();
			String[] flds = Strings.getfields(s, "/");
			if(flds.length != 0){
				if(!flds[0].equals("."))
					this.principal = new Principal(flds[0]);
				for(int i = 1; i < flds.length; i++)
					add(flds[i]);
			}
		}

		public Name add(String s){
			this.idents.add(s);
			return this;
		}

		public boolean hasNames(){
			return idents.size() > 0;
		}

		public boolean isLocalName(){
			return idents.size() == 1;
		}

		public boolean eq(Name n2){
			if(n2 == null)
				return false;
			if(principal == null){
				if(n2.principal != null)
					return false;
			}else if(!principal.eq(n2.principal))
				return false;
			return samenames(idents, n2.idents);
		}

		public void pack(ByteBuffer b){
			if(principal != null)
				principal.pack(b);
			else
				b.put((byte)'.');
			if(hasNames())
				b.put(Strings.bytes(path()));
		}

		String path(){
			StringBuilder bs = new StringBuilder(64);
			for(String n : idents){
				bs.append('/');
				bs.append(n);
			}
			return bs.toString();
		}

		public String toString(){
			StringBuilder bs = new StringBuilder(64);
			if(principal != null)
				bs.append(principal);
			else
				bs.append('.');
			bs.append(path());
			return bs.toString();
		}
	}

	public static class Tag implements Packable {
		public	String	value;	// TO DO: ArrayList<String> ops;

		public Tag(String value){
			if(value == null)
				value = "";
			this.value = value;
		}

		public boolean isall(){
			return value.equals("*");
		}

		public boolean isnone(){
			return value.equals("");
		}

		public Tag intersect(Tag t2){
			// intersect the elements
			if(this.value.equals("") || t2.value.equals(""))
				return new Tag("");
			String f1[] = Strings.getfields(this.value, ",");	// TO DO: better parser to handle nesting
			String f2[] = Strings.getfields(t2.value, ",");
			ArrayList<String> els = new ArrayList<String>();
			for(String e1 : f1){
				for(String e2 : f2){
					if(e1.equals("*"))
						return t2;		// * & x = x
					if(e2.equals("*"))
						return this;	// x & * = x
					if(e1.equals(e2))
						els.add(e1);
				}
			}
			StringBuilder br = new StringBuilder(64);
			for(String s : els){
				if(br.length() > 0)
					br.append(',');
				br.append(s);
			}
			return new Tag(br.toString());
		}				
				
		public String toString(){
			return "tag="+Strings.quote(value);
		}

		public void pack(ByteBuffer b){
			if(value.equals(""))
				b.put((byte)0);
			else
				b.put(Strings.bytes(value));
		}
	}

	public static class Signature {
		public	Hash	data;	// hash of data
		public	Principal signer;
		public	String	alg;		// sig[-encoding]-hash eg, rsa-pkcs1-sha1
		String	sa;
		String	enc;
		String	ha;
		public	PKsig	sig;

		public Signature(Hash data, Principal signer, String alg, PKsig sig){
			this.data = data;
			this.signer = signer;
			this.alg = alg;
			this.sig = sig;
			splitalg();
		}

		public Signature(String s) throws CryptoError {
			this(new Attrs(s));
		}

		public Signature(Attrs av) throws CryptoError {
			byte[] datahash = base16.dec(need(av, "data"));
			signer = new Principal(need(av, "signer"));	// no name reduction, must have had key in hand to sign
			alg = need(av, "alg");
			splitalg();
			if(ha == null)
				throw new CryptoError("no hash algorithm");
			// could put this in a table
			if(ha.equals("sha1"))
				data = new Hash("sha1", datahash);
			else if(ha.equals("md5"))
				data = new Hash("md5", datahash);
			else
				throw new CryptoError("unknown hash algorithm: "+ha);
			// could put this in a table
			sig = new PKsig(sa);
			if(sa.equals("rsa")){
				if(enc != null && !enc.equals("pkcs1"))
					throw new CryptoError("unknown signature encoding: "+enc);
				sig.init(av, "val");	// is there a better parameter name?
			}else if(sa.equals("dsa") || sa.equals("elgamal"))
				sig.init(av, "r", "s");
			else
				throw new CryptoError("unknown signature algorithm: "+sa);
		}

		void splitalg() {	// alg in form sig[-encode]-hash
			String[] flds = Strings.getfields(alg, "-");
			this.ha = null;
			this.enc = null;
			this.sa = "";	// any, unspecified
			if(flds.length > 0){
				this.sa = flds[0];
				if(flds.length > 2){
					this.enc = flds[1];
					this.ha = flds[2];
				}else if(flds.length > 1)
					this.ha = flds[1];
			}
		}

		public String toString(){
			return String.format("signature alg=%s data=%s signer=%s %s", alg, data, signer, sig);
		}
	}

	// generic SK creator
	public static final SK	genSK(String alg, int length) throws CryptoError {
		// could have a table with lambdas etc
		if(alg.equals("rsa"))
			return new RsaSK(length);
		// DSA is another plausible one
		throw new CryptoError("unknown/unsupported pk algorithm: "+alg);
	}

	// generic PK parser
	public static final PK parsePK(Key k) throws CryptoError {
		try{
			String alg = need(k.visible, "alg");
			if(alg.equals("rsa"))
				return new RsaPK(k);
			throw new CryptoError("unknown/unsupported pk algorithm: "+alg);
		}catch(InvalidKey e){
			throw new CryptoError("invalid key: "+e.getMessage());
		}
	}

	// generic SK parser
	public static final SK parseSK(Key k) throws CryptoError {
		try{
			String alg = need(k.visible, "alg");
			if(alg.equals("rsa"))
				return new RsaSK(k);
			throw new CryptoError("unknown/unsupported pk algorithm: "+alg);
		}catch(InvalidKey e){
			throw new CryptoError("invalid key: "+e.getMessage());
		}
	}

	// hash any Packable item using the given hash algorithm
	public static final Hash hash(String alg, Packable item) throws CryptoError {
		ByteBuffer b = ByteBuffer.allocate(8192);	// TO DO: work this out
		item.pack(b);
		if(alg.equals("sha1")){
			return new Hash("sha1", Aids.sha1(b.array(), 0, b.position(), null));
		}else if(alg.equals("md5")){
			throw new CryptoError("md5 not implemented");
		}else
			throw new CryptoError("unknown hash algorithm");
	}

	// sign any hashed data
	public static final Signature sign(Hash h, Principal signer) throws CryptoError {
		SK sk = signer.sk;
		if(sk == null)
			throw new CryptoError("signing Princpal lacks private key: "+signer);
		// TO DO: pkcs1
		PKsig sig = sk.sign(new BigInteger(1, h.value));
		return new Signature(h, signer, sig.alg+"-"+h.alg, sig);
	}

	// hash and sign a byte array
	public static final Signature sign(byte[] a, String halg, Principal signer) throws CryptoError {
		if(!halg.equals("sha1"))
			throw new CryptoError("unimplemented hash algorithm: "+halg);
		return sign(new Hash(halg, Aids.sha1(a)), signer);
	}

	// hash and sign a certificate
	public static final Signature sign(Certificate cert, String halg, Principal signer) throws CryptoError {
		return sign(hash(halg, cert), signer);
	}

	// auxiliary functions available to PK, SK implementations and others.

	static final String need(Attrs av, String n) throws CryptoError {
		String s = av.findattrval(n);
		if(s == null)
			throw new CryptoError("key/signature/certificate missing "+n+" attribute");
		return s;
	}

	static final String need(Key k, String n) throws InvalidKey {
		String s;
		if(n.length() > 0 && n.charAt(0) == '!')
			s = k.secrets.findattrval(n);
		else
			s = k.visible.findattrval(n);
		if(s == null)
			throw new InvalidKey("key missing "+n+" attribute");
		return s;
	}
}
