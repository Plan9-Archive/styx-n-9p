package com.vitanuova.auth;

//
// elements of Plan 9 authentication
//
// this is a near transliteration of Plan 9 source, subject to the Lucent Public License 1.02,
// via the Limbo P9auth module from Vita Nuova 2005
//

// throws

// rename to plan9.*

import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.vitanuova.lib.Packer;

public class P9auth {

	//
	// plan 9 authentication primitives
	//

	public static final int ANAMELEN = 	28; // maximum size of name in previous proto
	public static final int AERRLEN = 	64; // maximum size of errstr in previous proto
	public static final int DOMLEN = 		48; // length of an authentication domain name
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

	public class BAD extends Exception {
		public BAD(String s){ super(s); }
	}

	public static final int TICKREQLEN = 3*ANAMELEN+CHALLEN+DOMLEN+1;

	public class Ticketreq {
		public int rtype = 0;
		public String authid;		// [ANAMELEN]	server's encryption id
		public String authdom;	// [DOMLEN]	server's authentication domain
		public byte[] chal;	 	// [CHALLEN]	challenge from server
		public String hostid;		// [ANAMELEN]		host's encryption id
		public String uid;		// [ANAMELEN]	uid of requesting user on host

		Ticketreq(){}

		public final int packedsize(){ return TICKREQLEN; }

		public final void pack(Packer b) {
			b.put((byte)this.rtype);
			b.puts(f.authid, ANAMELEN);
			b.puts(f.authdom, DOMLEN);
			b.puta(f.chal, CHALLEN);
			b.puts(f.hostid, ANAMELEN);
			b.puts(f.uid, ANAMELEN);
		}
		public static final Ticketreq unpack(Packer b) throws BAD {
			Ticketreq f = new Ticketreq();
			f.rtype = (int)b.get();
			f.authid = b.gets(ANAMELEN);
			f.authdom = b.gets(DOMLEN);
			f.chal = b.geta(CHALLEN);
			f.hostid = b.gets(ANAMELEN);
			f.uid = b.gets(ANAMELEN);
			return f;
		}
	}

	public static final int TICKETLEN = CHALLEN+2*ANAMELEN+DESKEYLEN+1;
	public class Ticket {
		public int num;	// replay protection
		public byte[] chal;	// [CHALLEN]	server challenge
		public String cuid;	// [ANAMELEN]	uid on client
		public String suid;	// [ANAMELEN]	uid on server
		public byte[] key;	// [DESKEYLEN]	nonce DES key

		Ticket(int num, byte[] chal, String cuid, String suid, byte[] key){
			this.num = num;
			this.chal = chal;
			this.cuid = cuid;
			this.suid = suid;
			this.key = key;
		}

		public final static int packedsize() { return TICKETLEN; }
		
		public final byte[] pack(byte[] key){
			byte[] a = new byte[TICKETLEN];
			Arrays.fill(a, (byte)0);
			a[0] = (byte)this.num;
			puta(a, 1, this.chal, this.chal.length);
			puts(a, 1+CHALLEN, this.cuid, ANAMELEN);
			puts(a, 1+CHALLEN+ANAMELEN, this.suid, ANAMELEN);
			puta(a, 1+CHALLEN+2*ANAMELEN, this.key, this.key.length);
			if(key != nil)
				encrypt(key, a, a.length);
			return a;
		}

		public static final Ticket unpack(byte[] a, byte[] key){
			if(key != null)
				decrypt(key, a, TICKETLEN);
			int num = int a[0];
			byte[] chal = geta(a[1:], CHALLEN);
			String cuid = gets(a[1+CHALLEN:], ANAMELEN);
			String suid = gets(a[1+CHALLEN+ANAMELEN:], ANAMELEN);
			byte[] key = geta(a[1+CHALLEN+2*ANAMELEN:], DESKEYLEN);
			return new Ticket(num, chal, cuid, suid, key);
		}
	}

	public static final int AUTHENTLEN = CHALLEN+4+1;
	public class Authenticator {
		public int	num;		// replay protection
		public byte[]	chal;	// [CHALLEN]
		public int	id;		// authenticator id, ++'d with each auth

		Authenticator(int num, byte[] chal, int id){
			this.num = num;
			this.chal = chal;
			this.id = id;
		}

		public final int packedsize(){ return AUTHENTLEN; }

		public final byte[] pack(byte[] key){
			byte[] p = new byte[AUTHENTLEN];
			Arrays.fill(p, (byte)0);
			p[0] = (byte)this.num;
			puta(p, 1, this.chal, CHALLEN);
			put4(p, 1+CHALLEN, this.id);
			if(key != null)
				encrypt(key, p, p.length);
			return p;
		}

		public final Authenticator unpack(byte[] a, byte[] key){
			if(key != null)
				decrypt(key, a, AUTHENTLEN);
			int num = int a[0];
			byte[] chal = geta(a, 1, CHALLEN);
			int id = get4(a, 1+CHALLEN);
			return Authenticator(num, chal, id);
		}
	}

	Passwordreq: adt {
		num: int;
		old:	array of byte;	// [ANAMELEN]
		new:	array of byte;	// [ANAMELEN]
		changesecret:	int;
		secret:	array of byte; // [SECRETLEN]	new secret

		pack:	fn(f: self ref Passwordreq, key: array of byte): array of byte;
		unpack:	fn(a: array of byte, key: array of byte): (int, ref Passwordreq);

		Passwordreq.pack(f: self ref Passwordreq, key: array of byte): array of byte
		{
			a := array[PASSREQLEN] of {* => byte 0};
			a[0] = byte f.num;
			a[1:] = f.old;
			a[1+ANAMELEN:] = f.new;
			a[1+2*ANAMELEN] = byte f.changesecret;
			a[1+2*ANAMELEN+1:] = f.secret;
			if(key != nil)
				encrypt(key, a, len a);
			return a;
		}

		public Passwordreq unpack(byte[] a, byte[] key){
			if(key != null)
				decrypt(key, a, PASSREQLEN);
			f := ref Passwordreq;
			f.num = int a[0];
			f.old = geta(a[1:], ANAMELEN);
			f.old[ANAMELEN-1] = byte 0;
			f.new = geta(a[1+ANAMELEN:], ANAMELEN);
			f.new[ANAMELEN-1] = byte 0;
			f.changesecret = int a[1+2*ANAMELEN];
			f.secret = geta(a[1+2*ANAMELEN+1:], SECRETLEN);
			f.secret[SECRETLEN-1] = byte 0;
			return (PASSREQLEN, f);
		}
	}
	public static final int PASSREQLEN = 2*ANAMELEN+1+1+SECRETLEN;

	// dial auth server
//	authdial(netroot: string, authdom: string): ref Sys->FD;

	private static final void puts(ByteBuffer b, String s){
		byte[] a = bytes(s);
		p16(b, a.length);
		b.put(a);
	}
	private static final String gets(ByteBuffer b){
		int n = g16(b);
		byte[] a = new byte[n];
		b.get(a);
		try{
			return new String(a, "UTF-8");
		}catch(java.io.UnsupportedEncodingException e){
			return "Egosling";
		}
	}

	private static final int get1(ByteBuffer b){ return (int)b.get() & 0xFF; }

	private static final void put2(ByteBuffer b, int n){
		b.put((byte)n);
		b.put((byte)(n>>8));
	}
	private static final int get2(ByteBuffer b){
		int b0 = get1(b);
		return (get1(b) << 8) | b0;
	}

	private static final put2(byte[] a, int o, int v){
		a[o+0] = (byte)(v);
		a[o+1] = (byte)(v>>8);
	}

	private static final int get2(byte[] a, int o){
		return ((int)a[o+1]<<8) | (int)a[o+0];
	}

	private static final void put4(byte[] a, int o, int v){
		a[o+0] = (byte)v;
		a[o+1] = (byte)(v>>8);
		a[o+2] = (byte)(v>>16);
		a[o+3] = (byte)(v>>24);
	}

	private static final int get4(byte[] a, int o){
		return ((int)a[o+3]<<24) | ((int)a[o+2]<<16) | ((int)a[o+1]<<8) | (int)a[o+0];
	}

	private static final void puts(byte[] a, int o, String s, int n) {
		byte[] b = bytes(s);
		int l = b.length;
		if(l > n)
			l = n;
		System.arraycopy(b, 0, a, o, l);
		for(; l < n; l++)
			a[l] = (byte)0;
	}

	private static final String gets(byte[] b){
		try{
			return new String(b, "UTF-8");
		}catch(java.io.UnsupportedEncodingException e){
			return "Egosling";
		}
	}

	private static final byte[] geta(byte[] a, int o, int n){
		b = new byte[n];
		System.arraycopy(a, o, b, 0, n);
		return b;
	}

	/*
	 * SecureID and Plan 9 auth key/request/reply encryption (`netkey')
	 */
	public String netcrypt(byte[] key, String chal) {
		buf := array[8] of {* => byte 0};
		a := array of byte chal;
		if(len a > 7)
			a = a[0:7];
		buf[0:] = a;
		encrypt(key, buf, buf.length);
		return sys->sprint("%.2ux%.2ux%.2ux%.2ux", int buf[0], int buf[1], int buf[2], int buf[3]);
	}

	public final byte[] passtokey(String p){
		byte[] a = bytes(p);
		int n = a.length;
		if(n >= ANAMELEN)
			n = ANAMELEN-1;
		buf := array[ANAMELEN] of {* => byte ' '};
		buf[0:] = a[0:n];
		buf[n] = byte 0;
		key := array[DESKEYLEN] of {* => byte 0};
		t := 0;
		for(;;){
			for(i := 0; i < DESKEYLEN; i++)
				key[i] = byte ((int buf[t+i] >> i) + (int buf[t+i+1] << (8 - (i+1))));
			if(n <= 8)
				return key;
			n -= 8;
			t += 8;
			if(n < 8){
				t -= 8 - n;
				n = 8;
			}
			encrypt(key, buf[t:], 8);
		}
	}

	private static final byte[] parity = {
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
		int hi = (((int)k56[0]&0xFF)<<24)|(((int)k56[1]&0xFF)<<16)|(((int)k56[2]&0xFF)<<8)|((int)k56[3]&0xFF);
		int lo = (((int)k56[4]&0xFF)<<24)|(((int)k56[5]&0xFF)<<16)|(((int)k56[6]&0xFF)<<8);

		k64[0] = parity[(hi>>25)&0x7f];
		k64[1] = parity[(hi>>18)&0x7f];
		k64[2] = parity[(hi>>11)&0x7f];
		k64[3] = parity[(hi>>4)&0x7f];
		k64[4] = parity[((hi<<3)|int (lo>>>29))&0x7f];	// watch the sign extension
		k64[5] = parity[(lo>>22)&0x7f];
		k64[6] = parity[(lo>>15)&0x7f];
		k64[7] = parity[(lo>>8)&0x7f];
		return k64;
	}

	public final void encrypt(byte[] key, byte[] data, int n){
		int r, j;
		byte[] res;

		if(n < 8)
			return;
		SecretKeySpec key = new SecretKeySpec(des56to64(key), "DES");
		Cipher enc = Cipher.getInstance("DES/ECB/NoPadding");
		enc.init(Cipher.ENCRYPT_MODE, key, null);
		n--;
		r = n % 7;
		n /= 7;
		j = 0;
		for(i := 0; i < n; i++){
			res = enc.update(data, j, 8);
			System.arraycopy(res, 0, data, j, 8);
			j += 7;
		}
		if(r > 0){
			res = enc.update(data, j-7+r, 8);
			System.arraycopy(res, 0, data, j-7+r, 8);
		}
	}

	public final void decrypt(byte[] key, byte[] data, int n){
		int r, j;
		byte res[];

		if(n < 8)
			return;
		SecretKeySpec key = new SecretKeySpec(des56to64(key), "DES");
		Cipher dec = Cipher.getInstance("DES/ECB/NoPadding");
		dec.init(Cipher.DECRYPT_MODE, key, (AlgorithmParameterSpec)null);
		n--;
		r = n % 7;
		n /= 7;
		j = n*7;
		if(r > 0){
			res = dec.update(data, j-7+r, 8);
			System.arraycopy(res, 0, data, j-7+r, 8);
		}
		for(i := 0; i < n; i++){
			j -= 7;
			res = dec.update(data, j, 8);
			System.arraycopy(res, 0, data, j, 8);
		}
	}

	private final byte[] readn(ReadableByteStream fd, int nb){
		// wrap buf in ByteBuffer?
		byte[] buf = new byte[nb];
		for(int n = 0; n < nb;){
			int m = fd.read(
			m := sys->read(fd, buf[n:], nb-n);
			if(m <= 0)
				return nil;
			n += m;
		}
		return buf;
	}

	private final write(WritableByteChannel wfd, byte[] a) throws IOException {
		wfd.write(ByteBuffer.wrap(a));
	}

	private static final String pbmsg = "AS protocol botch";

	// returns server bits
	protected final byte[] _asgetticket(ReadableByteChannel rfd, WritableByteChannel wfd, tr: ref Ticketreq, key: array of byte, Ticket ticket) thows ASProtocolError, IOException {
		byte[] a;
		Ticket t;

		a = tr.pack();
		write(wfd, a);
		a = _asrdresp(fd, 2*TICKETLEN);
		if(a == null)
			return null;
		(nil, t) := Ticket.unpack(a, key);
		return (t, a[TICKETLEN:]);	// can't unpack both since the second uses server key
	}

	protected final byte[] _asrdresp(ReadableByteChannel fd, int n) throws ASProtocolError, IOException {
		byte[] b = read(fd, 1);	// could convert to null return
		if(b == null)
			throw new ASProtocolError("error reading from server");

		byte[] buf = null;
		switch((int)b[0]){
		case AuthOK:
			buf = readn(fd, n);
			break;
		case AuthOKvar:
			b = readn(fd, 5);
			if(b == null)
				break;
			n = Int.parse(S(b));
			if(n<= 0 || n > 4096)
				break;
			buf = readn(fd, n);
			break;
		case AuthErr:
			b = readn(fd, 64);
			if(b == nil)
				break;
			for(int i = 0; i<b.length && b[i] != 0; i++)
				{}
			sys->werrstr(sys->sprint("remote: %s", S(b, i)));
			return nil;
		default:
			sys->werrstr(sys->sprint("%s: resp %d", pbmsg, int b[0]));
			return nil;
		}
		if(buf == nil)
			sys->werrstr(pbmsg);
		return buf;
	}

	private static final String gets(byte[] b){
		try{
			return new String(b, "UTF-8");
		}catch(java.io.UnsupportedEncodingException e){
			return "Egosling";
		}
	}
}
