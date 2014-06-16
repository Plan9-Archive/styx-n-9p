package plan9.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.BufferOverflowException;

import java.lang.String;
import java.util.Arrays;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.Cipher;

import plan9.lib.Misc;
import plan9.Log;
import plan9.LogFactory;

//
// SSL/TLS record protocol
//
// SSL
//	b0 b1 b2
//	(b0&0x80) != 0 -> length = (b0<<8) | b1
//	(b0&0x80) == 0 ->
//		isescape = (b0 & 0x40)
//		npad = b2
//		length = ((b0&0x3F)<<8) | b1
//	record: b0 b1 b2? mac[p] data[n] pad[npad] where length=p+n
//	mac = H(secret, actual, padding, sequence[4])
//
// TLS
//	content[1] major[1] minor[1] length[2]{m} data[m] mac[p] padding[q]
//
public class Ssl {

	final static int AESbsize = 16;
	final static int SHA1dlen = 160/8;
	final static int MaxMsgLen = 1<<15;
	final static long Maxseq = 0xFFFFFFFFL;
	final static int Hdrlen = 2;	// basic header length in bytes
	final static String[][] algmap = {
		// first string is the canonical one
		new String[]{"SHA-1", "sha1", "sha"},
		new String[]{"RC4", "ARCFOUR", "rc4"},
	};
	final static Log log = LogFactory.logger(Ssl.class);

	static final String mapname(String name){	// return canonical name
		for(int i = 0; i < algmap.length; i++){
			String[] a = algmap[i];
			for(int j = 0; j < a.length; j++)
				if(a[i].equals(name))
					return a[0];
		}
		return name;
	}

	static class ConnState {
		// connection state
		byte[]	secret;	// SHA1dlen
		long	seqno;
		Encryption	cipher;
		MessageDigest	hashalg;

		byte[]	intb;
		byte[]	digest;
		byte[]	tmpdigest;
		int	digestlen;
		int	blocklen;
		int	maxpad;		// MaxMsgLen - digestlen - 1
		int	maxlen;

		byte[]	buf;
		int	rd;
		int	wr;
		int	res;
		int	cap;

		ByteBuffer	b;

		ConnState() {
			buf = new byte[MaxMsgLen+128];
			cap = MaxMsgLen+128;
			rd = 0;
			wr = 0;
			res = 0;
			b = ByteBuffer.wrap(buf);
			intb = new byte[4];	// [sizeof(int32)]
			digestlen = 0;
			blocklen = 1;	// we'll use stream cipher RC4 (full rc4 key length only, rc4_256)
			hashalg = null;
			seqno = 0;
			setmsglen();
		}
		void sethashalg(String name) throws NoSuchAlgorithmException {
			hashalg = MessageDigest.getInstance(mapname(name));
			digestlen = hashalg.getDigestLength();
			digest = new byte[digestlen];
			tmpdigest = new byte[digestlen];
			setmsglen();
		}
		void setencalg(String name) throws NoSuchAlgorithmException {
			if(name.equals("rc4")){
				blocklen = 1;
				setmsglen();
			}else if(name.equals("aes")){
				blocklen = AESbsize;
				setmsglen();
			}else
				throw new NoSuchAlgorithmException(name);
		}
		void setmsglen(){
			maxlen = 1<<15;
			if(blocklen != 1){
				maxlen -= maxlen % blocklen;
				maxpad = (MaxMsgLen>>1) - digestlen - 1;
				maxpad -= maxpad % blocklen;
			}else
				maxpad = MaxMsgLen - digestlen - 1;
		}

	}
	ConnState in = new ConnState();
	ConnState out = new ConnState();
	boolean encrypting = false;
	boolean digesting = false;

	// separate read and write channels to allow use of Java's Pipe for testing
	ReadableByteChannel	rfd;
	WritableByteChannel	wfd;

	public Ssl(ReadableByteChannel rfd, WritableByteChannel wfd) throws NoSuchAlgorithmException {
		this.rfd = rfd;
		this.wfd = wfd;
		in = new ConnState();
		out = new ConnState();
	}
	public Ssl(ByteChannel fd) throws NoSuchAlgorithmException {
		this(fd, fd);
	}

	public void setalg(String haname, String encname) throws NoSuchAlgorithmException {
		if(haname != null && !haname.equals("")){
			in.sethashalg(haname);
			out.sethashalg(haname);
		}
		// ignore encname for now
	}
	public void setsecret(byte[] secret, int dir){
		for(int i = 0; i < 2; i++){
			if((dir & (1<<i)) != 0){
				ConnState x = i==1? out: in;
				x.secret = new byte[secret.length];
				System.arraycopy(secret, 0, x.secret, 0, secret.length);
			}
		}
	}
	public void startdigest(){
		if(in.hashalg != null)
			digesting = true;
	}
	public void stopdigest(){
		digesting = false;
	}
	public void startcrypt(){
		in.cipher = new RC4(in.secret);
		out.cipher = new RC4(out.secret);
		encrypting = true;
	}
	public void stopcrypt(){
		encrypting = false;
	}
	public void restartcrypt(){
		encrypting = true;
	}

	byte[] hash(MessageDigest hasher, byte[] hashed, byte[] secret, byte[] data, int offset, int len, byte[] sb){
		hasher.reset();
		if(secret != null)
			hasher.update(secret);
		hasher.update(data, offset, len);
		hasher.update(sb);
		try{
			hasher.digest(hashed, 0, hashed.length);	// n.b. digest(x) is x as input, x is output in digest(x, off, len)
		}catch(DigestException e){
			Arrays.fill(hashed, (byte)0xFF);
		}
		if(false && log.tracing())
			log.trace("hash: %s [%d]%s %s -> %s", Misc.dump(secret), len, Misc.dump(data, offset, offset+len), Misc.dump(sb), Misc.dump(hashed));
		return hashed;
	}

	void compact(){
		System.arraycopy(in.buf, in.rd, in.buf, 0, in.wr-in.rd);
		in.wr -= in.rd;
		in.rd = 0;
		in.b.position(in.wr);
	}

	boolean fill(int n, boolean reqd) throws IOException {
		while(in.wr < in.rd+n){
			if(in.cap - in.rd < n)
				compact();
			in.b.position(in.wr);
			if(rfd.read(in.b) <= 0){
				if(!reqd)
					return false;
				throw new IOException("unexpected end-of-file");
			}
			in.wr = in.b.position();
		}
		return true;
	}

	int get(){ return in.buf[in.rd++] & 0xFF; }

	// return count of bytes available at in.buf[in.rd]
	int fillbuf() throws IOException {
		if(!fill(Hdrlen, false))
			return 0;
		int b0 = get();
		int b1 = get();
		int npad = 0;
		boolean isesc = false;
		if((b0 & 0x80) == 0){	// padded
			isesc = (b0 & 0x40) != 0;
			b0 &= ~0x40;
			if(!fill(1, true))
				throw new IOException("missing ssl pad value byte");
			npad = get();
		}else
			b0 &= ~0x80;
		int length = (b0 << 8) | b1;
		if(length > MaxMsgLen)
			throw new IOException("incoming ssl message too long");
		if(npad > length)
			throw new IOException("bad pad in ssl message");
		if(!fill(length, true))
			throw new IOException("incoming ssl message truncated");
		if(encrypting)
			in.cipher.decrypt(in.buf, in.rd, length);
		if(digesting){
			if(length < in.digestlen)
				throw new IOException("incoming ssl message too short");
			System.arraycopy(in.buf, in.rd, in.tmpdigest, 0, in.digestlen);
			in.rd += in.digestlen;
			length -= in.digestlen;
			put4(in.intb, (int)in.seqno);
			hash(in.hashalg, in.digest, in.secret, in.buf, in.rd, length, in.intb);
			if(log.tracing())
				log.trace("seq: %d dig.in: %s dig.our: %s data: %s",
					in.seqno, Misc.dump(in.tmpdigest), Misc.dump(in.digest), Misc.dump(in.buf, in.rd, in.rd+length));
			if(!Arrays.equals(in.tmpdigest, in.digest))
				throw new IOException("integrity check failed");
		}
		in.seqno++;
		if(in.seqno > Maxseq)
			in.seqno = 0;
		return length;
	}

	public byte[] read() throws IOException {
		int length = in.res;
		if(length == 0){
			length = fillbuf();
			if(length == 0)
				return null;
		}else
			in.res -= length;
		byte[] buf = new byte[length];
		System.arraycopy(in.buf, in.rd, buf, 0, length);
		in.rd += length;
		return buf;
	}

	public int read(ByteBuffer b) throws IOException {
		int rem = b.remaining();
		if(rem == 0)
			throw new IOException("no space in buffer");
		int length = in.res;
		if(length > rem)
			length = rem;
		if(length == 0){
			length = fillbuf();
			if(length == 0)
				return 0;
			if(length > rem){
				in.res = length-rem;
				length = rem;
			}
		}else
			in.res -= length;
		if(false && b.hasArray()){
			int p = b.position();
			System.arraycopy(in.buf, in.rd, b.array(), b.arrayOffset()+p, length);
			b.position(p+length);
		}else
			b.put(in.buf, in.rd, length);
		in.rd += length;
		return length;
	}

	public void write(byte[] buf, int o, int n) throws IOException {
		while(n > 0){
			int m = n;
			int pad = 0;
			int h = out.digestlen + Hdrlen;
			if(m > out.maxlen)
				m = out.maxlen;
			else if(out.blocklen != 1){
				pad = (m+out.digestlen) % out.blocklen;
				if(pad > 0){
					if(m > out.maxpad){
						m = out.maxpad;
						pad = 0;
					}else{
						pad = out.blocklen - pad;
						h++;
					}
				}
			}
			out.b.clear();
			byte[] p = out.buf;
			int hlen = Hdrlen;	// header length
			int len = m + pad;	// data length
			int dataoffset = hlen;
			if(digesting){
				len += out.digestlen;
				dataoffset += out.digestlen;
			}
			if(pad != 0){
				p[0] = (byte)(len>>8);
				p[1] = (byte)len;
				p[2] = (byte)pad;
				hlen++;
			}else{
				p[0] = (byte)((len>>8)|0x80);
				p[1] = (byte)len;
			}
			System.arraycopy(buf, 0, p, dataoffset, m);
			if(pad > 0){
				int padoffset = dataoffset + m;
				Arrays.fill(p, padoffset, padoffset+pad, (byte)pad);	// for TLS it's the pad length
			}
			if(digesting){
				put4(out.intb, (int)out.seqno);
				hash(out.hashalg, out.digest, out.secret, p, dataoffset, m+pad, out.intb);
				System.arraycopy(out.digest, 0, p, hlen, out.digestlen);
			}
			if(encrypting)
				out.cipher.encrypt(out.buf, hlen, len);
			out.b.position(hlen+len);
			out.b.flip();
			wfd.write(out.b);
			out.seqno++;
			if(out.seqno > Maxseq)
				out.seqno = 0;
			o += m;
			n -= m;
		}
	}

	public int write(ByteBuffer b) throws IOException {
		// assume a backing array for now
		int length = b.remaining();
		int p = b.position();
		write(b.array(), b.arrayOffset()+p, length);
		b.position(p+length);
		return length;
	}

	public void close() throws IOException {
		rfd.close();
		wfd.close();
	}
	void put4(byte[] sb, int seq){
		sb[0] = (byte)(seq>>24);
		sb[1] = (byte)(seq>>16);
		sb[2] = (byte)(seq>>8);
		sb[3] = (byte)seq;
	}

	public static final Ssl push(ReadableByteChannel rfd, WritableByteChannel wfd, String ealg, byte[] secin, byte[] secout) throws NoSuchAlgorithmException, IOException {
		if(log.debugging())
			log.debug("pushssl: alg %s secin %s secout %s", ealg, Misc.dump(secin), Misc.dump(secout));
		Ssl ssl = new Ssl(rfd, wfd);
		ssl.setsecret(secin, 1<<0);
		ssl.setsecret(secout, 1<<1);
		ssl.setalg("sha1", ealg);
		ssl.startdigest();
		ssl.startcrypt();
		return ssl;
	}

	public static final Ssl push(ByteChannel fd, String ealg, byte[] secin, byte[] secout) throws NoSuchAlgorithmException, IOException {
		return push(fd, fd, ealg, secin, secout);
	}
}
