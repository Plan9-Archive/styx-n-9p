package plan9.auth;

//
// elements of Plan 9 authentication
//
// this is a near transliteration of Plan 9 source, subject to the Lucent Public License 1.02,
// via the Limbo P9auth module from Vita Nuova 2005
//

// Java version moved here from com.vitanuova.auth.P9auth
// revisions Copyright © 2012 Coraid Inc

// throws

import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.nio.*;
import java.nio.channels.ByteChannel;
import java.nio.channels.ClosedByInterruptException;

import java.util.Arrays;

import plan9.lib.Misc;
import plan9.lib.Packer;
import plan9.lib.Strings;

public class P9auth {

	//
	// plan 9 authentication primitives
	//

	public static final int ANAMELEN = 	28; // maximum size of name in previous proto
	public static final int AERRLEN = 	64; // maximum size of errstr in previous proto
	public static final int DOMLEN = 	48; // length of an authentication domain name
	public static final int DESKEYLEN = 	7; // length of a des key for encrypt/decrypt
	public static final int CHALLEN = 	8; // length of a plan9 sk1 challenge
	public static final int NETCHLEN = 	16; // max network challenge length (used in AS protocol)
	public static final int SECRETLEN = 	32; // max length of a secret

	// encryption numberings (anti-replay)
	public static final int AuthTreq = 1; 	// ticket request
	public static final int AuthChal = 2; 	// challenge box request
	public static final int AuthPass = 3; 	// change password
	public static final int AuthOK = 4; 	// fixed length reply follows
	public static final int AuthErr = 5; 	// error follows
	public static final int AuthMod = 6; 	// modify user
	public static final int AuthApop = 7; 	// apop authentication for pop3
	public static final int AuthOKvar = 9; 	// variable length reply follows
	public static final int AuthChap = 10; 	// chap authentication for ppp
	public static final int AuthMSchap = 11; 	// MS chap authentication for ppp
	public static final int AuthCram = 12; 	// CRAM verification for IMAP (RFC2195 & rfc2104)
	public static final int AuthHttp = 13; 	// http domain login
	public static final int AuthVNC = 14; 	// VNC server login (deprecated)

	public static final int AuthTs = 64;	// ticket encrypted with server's key
	public static final int AuthTc = 65;	// ticket encrypted with client's key
	public static final int AuthAs = 66;	// server generated authenticator
	public static final int AuthAc = 67;	// client generated authenticator
	public static final int AuthTp = 68;	// ticket encrypted with client's key for password change
	public static final int AuthHr = 69;	// http reply

	public static final int TICKREQLEN = 3*ANAMELEN+CHALLEN+DOMLEN+1;

	public static class Ticketreq {
		public int rtype = 0;
		public String authid;		// [ANAMELEN]	server's encryption id
		public String authdom;	// [DOMLEN]	server's authentication domain
		public byte[] chal;	 	// [CHALLEN]	challenge from server
		public String hostid;		// [ANAMELEN]		host's encryption id
		public String uid;		// [ANAMELEN]	uid of requesting user on host

		public Ticketreq(){}

		public Ticketreq(int rtype, String authid, String authdom, byte[] chal, String hostid, String uid){
			this.rtype = rtype;
			this.authid = authid;
			this.authdom = authdom;
			this.chal = chal;
			this.hostid = hostid;
			this.uid = uid;
		}

		public int packedsize(){ return TICKREQLEN; }

		public final void pack(Packer b) {
			b.put1(rtype);
			b.puts(authid, ANAMELEN);
			b.puts(authdom, DOMLEN);
			b.puta(chal, CHALLEN);
			b.puts(hostid, ANAMELEN);
			b.puts(uid, ANAMELEN);
		}
		public Ticketreq unpack(Packer b) {
			rtype = b.get1();
			authid = b.gets(ANAMELEN);
			authdom = b.gets(DOMLEN);
			chal = b.geta(CHALLEN);
			hostid = b.gets(ANAMELEN);
			uid = b.gets(ANAMELEN);
			return this;
		}
	}

	public static final int TICKETLEN = CHALLEN+2*ANAMELEN+DESKEYLEN+1;
	public static class Ticket {
		public int num;	// replay protection
		public byte[] chal;	// [CHALLEN]	server challenge
		public String cuid;	// [ANAMELEN]	uid on client
		public String suid;	// [ANAMELEN]	uid on server
		public byte[] key;	// [DESKEYLEN]	nonce DES key

		public Ticket(){}

		public Ticket(int num, byte[] chal, String cuid, String suid, byte[] key){
			this.num = num;
			this.chal = chal;
			this.cuid = cuid;
			this.suid = suid;
			this.key = key;
		}

		public int packedsize() { return TICKETLEN; }
		
		public final void pack(Packer b, byte[] ckey) throws CryptoError {
			int o = b.offset();
			b.put1(num);
			b.puta(this.chal, CHALLEN);
			b.puts(cuid, ANAMELEN);
			b.puts(suid, ANAMELEN);
			b.puta(key, DESKEYLEN);
			if(ckey != null)
				encrypt(ckey, b.array(), o, TICKETLEN);
		}

		public Ticket unpack(Packer b, byte[] ckey) throws CryptoError {
			if(ckey != null)
				decrypt(ckey, b.array(), b.offset(), TICKETLEN);
			num = b.get1();
			chal = b.geta(CHALLEN);
			cuid = b.gets(ANAMELEN);
			suid = b.gets(ANAMELEN);
			key = b.geta(DESKEYLEN);
			return this;
		}
	}

	public static class TicketPair {
		public Ticket	known;	// was encrypted by Kc; unpacked
		public byte[]	hidden;	// encrypted by Ks, still packed

		public TicketPair(Ticket known, byte[] hidden){
			this.known = known;
			this.hidden = hidden;
		}
	}

	public static final int AUTHENTLEN = CHALLEN+4+1;
	public static class Authenticator {
		public int	num;		// replay protection
		public byte[]	chal;	// [CHALLEN]
		public int	id;		// authenticator id, ++'d with each auth

		public Authenticator(){}

		public Authenticator(int num, byte[] chal, int id){
			this.num = num;
			this.chal = chal;
			this.id = id;
		}

		public int packedsize(){ return AUTHENTLEN; }

		public final void pack(Packer b, byte[] key) throws CryptoError {
			int o = b.offset();
			b.put1(num);
			b.puta(chal, CHALLEN);
			b.put4(id);
			if(key != null)
				encrypt(key, b.array(), o, AUTHENTLEN);
		}

		public Authenticator unpack(Packer b, byte[] key) throws CryptoError {
			if(key != null)
				decrypt(key, b.array(), b.offset(), AUTHENTLEN);
			num = b.get1();
			chal = b.geta(CHALLEN);
			id = b.get4();
			return this;
		}
	}

	public static final int PASSREQLEN = 2*ANAMELEN+1+1+SECRETLEN;
	public static class Passwordreq {
		public int	num;
		public byte[]	oldpw;		// [ANAMELEN]
		public byte[]	newpw;		// [ANAMELEN]
		public boolean	changesecret;
		public byte[]	secret;	// [SECRETLEN]

		public Passwordreq(){}

		public Passwordreq(int num, byte[] oldpw, byte[] newpw, boolean changesecret, byte[] secret){
			this.num = num;
			this.oldpw = oldpw;
			this.newpw = newpw;
			this.changesecret = changesecret;
			this.secret = secret;
		}

		public int packedsize(){ return PASSREQLEN; }

		public final void pack(Packer b, byte[] key) throws CryptoError {
			b.put1(num);
			b.puta(oldpw, ANAMELEN);
			b.puta(newpw, ANAMELEN);
			b.put(changesecret? (byte)1: (byte)0);
			b.puta(secret, SECRETLEN);
			if(key != null)
				encrypt(key, b.array(), b.offset()-PASSREQLEN, PASSREQLEN);
		}

		public Passwordreq unpack(Packer b, byte[] key) throws CryptoError {
			if(key != null)
				decrypt(key, b.array(), b.offset(), PASSREQLEN);
			num = b.get1();
			oldpw = b.geta(ANAMELEN);
			oldpw[ANAMELEN-1] = (byte)0;
			newpw = b.geta(ANAMELEN);
			newpw[ANAMELEN-1] = (byte)0;
			changesecret = b.get() != (byte)0;
			secret = b.geta(SECRETLEN);
			secret[SECRETLEN-1] = (byte)0;
			return this;
		}
	}

	final static int UB(byte b){ return (int)b&0xFF; }

	/*
	 * SecureID and Plan 9 auth key/request/reply encryption (`netkey')
	 */
	public String netcrypt(byte[] key, String chal) throws CryptoError {
		byte[] buf = new byte[8];
		Arrays.fill(buf, (byte)0);
		byte[] a = Strings.bytes(chal);
		int l = a.length;
		if(l > DESKEYLEN)
			l = DESKEYLEN;
		System.arraycopy(a, 0, buf, 0, l);
		encrypt(key, buf, 0, buf.length);
		return String.format("%02x%02x%02x%02x", UB(buf[0]), UB(buf[1]), UB(buf[2]), UB(buf[3]));
	}

	public byte[] passtokey(String p) throws CryptoError {
		byte[] a = Strings.bytes(p);
		int n = a.length;
		if(n >= ANAMELEN)
			n = ANAMELEN-1;
		byte[] buf = new byte[ANAMELEN];
		Arrays.fill(buf, (byte)' ');
		System.arraycopy(a, 0, buf, 0, n);
		buf[n] = (byte)0;
		byte[] key = new byte[DESKEYLEN];
		Arrays.fill(key, (byte)0);
		int t = 0;
		for(;;){
			for(int i = 0; i < DESKEYLEN; i++)
				key[i] = (byte)((UB(buf[t+i]) >> i) + (UB(buf[t+i+1]) << (8 - (i+1))));
			if(n <= 8)
				return key;
			n -= 8;
			t += 8;
			if(n < 8){
				t -= 8 - n;
				n = 8;
			}
			encrypt(key, buf, t, 8);
		}
	}

	private static final short[] parity = {
		0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e, 
		0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 
		0x20, 0x23, 0x25, 0x26, 0x29, 0x2a, 0x2c, 0x2f, 
		0x31, 0x32, 0x34, 0x37, 0x38, 0x3b, 0x3d, 0x3e, 
		0x40, 0x43, 0x45, 0x46, 0x49, 0x4a, 0x4c, 0x4f, 
		0x51, 0x52, 0x54, 0x57, 0x58, 0x5b, 0x5d, 0x5e, 
		0x61, 0x62, 0x64, 0x67, 0x68, 0x6b, 0x6d, 0x6e, 
		0x70, 0x73, 0x75, 0x76, 0x79, 0x7a, 0x7c, 0x7f, 
		0x80, 0x83, 0x85, 0x86, 0x89, 0x8a, 0x8c, 0x8f, 
		0x91, 0x92, 0x94, 0x97, 0x98, 0x9b, 0x9d, 0x9e, 
		0xa1, 0xa2, 0xa4, 0xa7, 0xa8, 0xab, 0xad, 0xae, 
		0xb0, 0xb3, 0xb5, 0xb6, 0xb9, 0xba, 0xbc, 0xbf, 
		0xc1, 0xc2, 0xc4, 0xc7, 0xc8, 0xcb, 0xcd, 0xce, 
		0xd0, 0xd3, 0xd5, 0xd6, 0xd9, 0xda, 0xdc, 0xdf, 
		0xe0, 0xe3, 0xe5, 0xe6, 0xe9, 0xea, 0xec, 0xef, 
		0xf1, 0xf2, 0xf4, 0xf7, 0xf8, 0xfb, 0xfd, 0xfe,
	};

	public static final byte[] des56to64(byte[] k56){
		byte[] k64 = new byte[8];
		int hi = (UB(k56[0])<<24) | (UB(k56[1])<<16) | (UB(k56[2])<<8) | UB(k56[3]);
		int lo = (UB(k56[4])<<24) | (UB(k56[5])<<16) | (UB(k56[6])<<8);

		k64[0] = (byte)parity[(hi>>25)&0x7f];
		k64[1] = (byte)parity[(hi>>18)&0x7f];
		k64[2] = (byte)parity[(hi>>11)&0x7f];
		k64[3] = (byte)parity[(hi>>4)&0x7f];
		k64[4] = (byte)parity[((hi<<3)|(int)(lo>>>29))&0x7f];	// watch the sign extension
		k64[5] = (byte)parity[(lo>>22)&0x7f];
		k64[6] = (byte)parity[(lo>>15)&0x7f];
		k64[7] = (byte)parity[(lo>>8)&0x7f];
		return k64;
	}

	final static Cipher initdes(byte[] key, int mode) throws CryptoError {
		return Aids.initcipher("DES/ECB/NoPadding", des56to64(key), mode);
	}

	public final static void encrypt(byte[] key, byte[] data, int o, int n) throws CryptoError {
		int r, j;
		byte[] res;

		if(n < 8)
			throw new CryptoError("length less than block size");
		Cipher enc = initdes(key, Cipher.ENCRYPT_MODE);
		n--;
		r = n % 7;
		n /= 7;
		j = o;
		for(int i = 0; i < n; i++){
			res = enc.update(data, j, 8);
			System.arraycopy(res, 0, data, j, 8);
			j += 7;
		}
		if(r > 0){
			res = enc.update(data, j-7+r, 8);
			System.arraycopy(res, 0, data, j-7+r, 8);
		}
	}

	public final static void decrypt(byte[] key, byte[] data, int o, int n) throws CryptoError {
		int r, j;
		byte res[];

		if(n < 8)
			throw new CryptoError("length less than block size");
		Cipher dec = initdes(key, Cipher.DECRYPT_MODE);
		n--;
		r = n % 7;
		n /= 7;
		j = o + n*7;
		if(r > 0){
			res = dec.update(data, j-7+r, 8);
			System.arraycopy(res, 0, data, j-7+r, 8);
		}
		for(int i = 0; i < n; i++){
			j -= 7;
			res = dec.update(data, j, 8);
			System.arraycopy(res, 0, data, j, 8);
		}
	}

	private final static byte[] readn(ByteChannel fd, int nb) throws AuthProtoErr {
		try{
			return Misc.readn(fd, nb);
		}catch(ClosedByInterruptException e){
			throw new AuthProtoErr("interrupted by time-out", e);
		}catch(IOException e){
			throw new AuthProtoErr("read error: "+e.getMessage(), e);
		}
	}

	private final void write(ByteChannel fd, byte[] a) throws AuthProtoErr {
		try{
			fd.write(ByteBuffer.wrap(a));
		}catch(ClosedByInterruptException e){
			throw new AuthProtoErr("interrupted by time-out", e);
		}catch(IOException e){
			throw new AuthProtoErr("write error: "+e.getMessage(), e);
		}
	}

	private static final String pbmsg = "AS protocol botch";

	public final TicketPair _asgetticket(ByteChannel fd, Ticketreq tr, byte[] key) throws AuthProtoErr, LocalAuthErr, RemoteAuthErr {
		byte[] a = new byte[TICKREQLEN];
		tr.pack(new Packer(a));
		write(fd, a);
		a = _asrdresp(fd, 2*TICKETLEN);
		Packer p = new Packer(a);
		Ticket t;
		try{
			t = (new Ticket()).unpack(p, key);
		}catch(CryptoError e){
			throw new LocalAuthErr(e.getMessage(), e);
		}
		byte[] s = p.geta(TICKETLEN);
		return new TicketPair(t, s);
	}

	TicketPair mktickets(Ticketreq tr, byte[] key) throws CryptoError {
		Ticket tc, ts;
		byte[] randkey, a;

		if(!tr.authid.equals(tr.hostid))
			return null;

		randkey = new byte[DESKEYLEN];
		Aids.memrandom(randkey, 0, randkey.length);
		tc = new Ticket(AuthTc, tr.chal, tr.uid, tr.uid, randkey);
		ts = new Ticket(AuthTs, tr.chal, tr.uid, tr.uid, randkey);
		a = new byte[TICKETLEN];
		ts.pack(new Packer(a), key);
		return new TicketPair(tc, a);
	}

	public final byte[] _asrdresp(ByteChannel fd, int n) throws AuthProtoErr, RemoteAuthErr {
		byte[] b = readn(fd, 1);	// could convert to null return
		if(b == null)
			throw new AuthProtoErr("error reading from server");

		byte[] buf = null;
		switch((int)b[0]){
		case AuthOK:
			buf = readn(fd, n);
			break;
		case AuthOKvar:
			b = readn(fd, 5);
			if(b == null)
				break;
			n = Integer.parseInt(Strings.S(b));
			if(n<= 0 || n > 4096)
				break;
			buf = readn(fd, n);
			break;
		case AuthErr:
			b = readn(fd, 64);
			if(b == null)
				break;
			int i;
			for(i = 0; i<b.length && b[i] != (byte)0; i++)
				{}
			throw new RemoteAuthErr(String.format("remote: %s", Strings.S(b, 0, i)));
		default:
			throw new AuthProtoErr(String.format("%s: resp %d", pbmsg, (int)b[0]));
		}
		if(buf == null)
			throw new AuthProtoErr(pbmsg);
		return buf;
	}
}
