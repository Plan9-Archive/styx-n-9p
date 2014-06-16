package plan9.ssl;

import java.util.Arrays;

import java.io.IOException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.channels.ByteChannel;
import java.nio.ByteBuffer;

import java.security.NoSuchAlgorithmException;

import plan9.Log;
import plan9.LogFactory;

import plan9.lib.Misc;
import plan9.lib.Base16;
import plan9.lib.Base64;
import plan9.auth.Aids;
import plan9.auth.AuthenticationException;
import plan9.auth.CryptoError;

// "LineCrypt" is not a good name: think of a better one
public class LineCrypt {

	static final Base16 b16 = new Base16();
	static final Base64 b64 = new Base64();

	static final Log log = LogFactory.logger(LineCrypt.class);

	public static final Ssl sslserver(ReadableByteChannel rfd, WritableByteChannel wfd, byte[] secret) throws NoSuchAlgorithmException, CryptoError, IOException {

		byte[]	key = new byte[128/8];
		byte[]	digest = new byte[Aids.SHA1dlen];
		byte[]	fromclientsecret = new byte[Aids.SHA1dlen/2];
		byte[]	fromserversecret = new byte[Aids.SHA1dlen/2];

		if(log.debugging())
			log.debug("server master-secret %s", Misc.dump(secret));

		int n = key.length - 4;
		if(n > secret.length)
			n = secret.length;
		Arrays.fill(key, (byte)0xFF);
		System.arraycopy(secret, 0, key, 4, n);

		// exchange random numbers
		Aids.memrandom(key, 12, 4);
		wfd.write(ByteBuffer.wrap(key, 12, 4));
		if(Misc.readn(rfd, key, 0, 4) == null)
			throw new IOException("sslserver: unexpected end-of-file");

		// scramble into two secrets
		Aids.sha1(key, digest);
		System.arraycopy(digest, 0, fromclientsecret, 0, fromclientsecret.length);
		System.arraycopy(digest, fromclientsecret.length, fromserversecret, 0, fromserversecret.length);
		// set up encryption
		return Ssl.push(rfd, wfd, "rc4", cvkey(fromserversecret), cvkey(fromclientsecret));
	}

	public static final Ssl sslserver(ByteChannel fd, byte[] secret) throws NoSuchAlgorithmException, CryptoError, IOException {
		return sslserver(fd, fd, secret);
	}

	public static final Ssl sslclient(ReadableByteChannel rfd, WritableByteChannel wfd, byte[] secret) throws NoSuchAlgorithmException, CryptoError, IOException {

		byte[]	key = new byte[128/8];
		byte[]	digest = new byte[Aids.SHA1dlen];
		byte[]	fromclientsecret = new byte[Aids.SHA1dlen/2];
		byte[]	fromserversecret = new byte[Aids.SHA1dlen/2];

		if(log.debugging())
			log.debug("client master-secret %s", Misc.dump(secret));

		int n = key.length - 4;
		if(n > secret.length)
			n = secret.length;
		Arrays.fill(key, (byte)0xFF);
		System.arraycopy(secret, 0, key, 4, n);

		// exchange random numbers
		Aids.memrandom(key, 0, 4);
		wfd.write(ByteBuffer.wrap(key, 0, 4));
		if(Misc.readn(rfd, key, 12, 4) == null)
			throw new IOException("sslclient: unexpected end-of-file");

		// scramble into two secrets
		Aids.sha1(key, digest);
		System.arraycopy(digest, 0, fromclientsecret, 0, fromclientsecret.length);
		System.arraycopy(digest, fromclientsecret.length, fromserversecret, 0, fromserversecret.length);

		// set up encryption
		return Ssl.push(rfd, wfd, "rc4", cvkey(fromclientsecret), cvkey(fromserversecret));
	}

	public static final Ssl sslclient(ByteChannel fd, byte[] secret) throws NoSuchAlgorithmException, CryptoError, IOException {
		return sslclient(fd, fd, secret);
	}

	// Plan 9's import/export protocol takes the key parts above, converts to lower-case hex, and
	// passes them to ssl(3) or tls(3)'s control file as "secretin" and "secretout", interpreted as base64 encodings.
	// Do the same here to get the right encryption key.
	static final byte[] cvkey(byte[] key){
		return b64.dec(hex(key));
	}

	static final String hex(byte[] a){
		StringBuilder bs = new StringBuilder(64);
		for(int i = 0; i < a.length; i++)
			bs.append(String.format("%02x", (int)a[i] & 0xFF));	// lower case, unlike Base16.enc
		return bs.toString();
	}
}
