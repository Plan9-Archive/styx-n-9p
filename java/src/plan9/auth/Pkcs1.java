package plan9.auth;

//
// apply PKCS#1 encoding to a hash value before an RSA public-key operation
//
// adapted from spki.b

import java.util.Arrays;

public class Pkcs1 {

	//
	// pkcs1 asn.1 DER encodings
	//

	static final byte[] pkcs1_md5_pfx = {
		(byte)0x30, (byte)32,                 // SEQUENCE in 32 bytes
			(byte)0x30, (byte)12,                 // SEQUENCE in 12 bytes
				(byte)6, (byte)8,                     // OBJECT IDENTIFIER in 8 bytes
					(byte)(40*1+2),                   // iso(1) member-body(2)
					(byte)(0x80 + 6), (byte)72,             // US(840)
					(byte)(0x80 + 6), (byte)(0x80 + 119), (byte)13, // rsadsi(113549)
					(byte)2,                        // digestAlgorithm(2)
					(byte)5,                        // md5(5), end of OBJECT IDENTIFIER
				(byte)0x05, (byte)0,                  // NULL parameter, end of SEQUENCE
			(byte)0x04, (byte)16             //OCTET STRING in 16 bytes (MD5 length)
	} ; 

	static final byte[] pkcs1_sha1_pfx = {
		(byte)0x30, (byte)33,               // SEQUENCE in 33 bytes
			(byte)0x30, (byte)9,                 // SEQUENCE in 9 bytes
				(byte)6, (byte)5,                    // OBJECT IDENTIFIER in 5 bytes
					(byte)(40*1+3),                  // iso(1) member-body(3)
					(byte)14,                      // ??(14)
					(byte)3,                       // ??(3)
					(byte)2,                       // digestAlgorithm(2)
					(byte)26,                     // sha1(26), end of OBJECT IDENTIFIER
				(byte)0x05, (byte)0,          // NULL parameter, end of SEQUENCE
			(byte)0x40, (byte)20	// OCTET STRING in 20 bytes (SHA1 length)
	};

	//
	// mlen should be key length in bytes
	//
	public static final byte[] pkcs1_encode(String ha, byte[] hash, int mlen) throws CryptoError {
		// apply hash function to message
		byte[] prefix;
		if(ha.equals("md5"))
			prefix = pkcs1_md5_pfx;
		else if(ha.equals("sha") || ha.equals("sha1"))
			prefix = pkcs1_sha1_pfx;
		else
			throw new CryptoError("invalid hash algorithm: "+ha);
		int tlen = prefix.length + hash.length;
		if(mlen < tlen + 11)
			throw new CryptoError("intended encoded message length too short");
		// add the wizard ASN.1 crud and the pad
		int pslen = mlen - tlen - 3;
		byte[] out = new byte[mlen];
		out[0] = (byte)0;
		out[1] = (byte)1;
		Arrays.fill(out, 2, 2+pslen, (byte)0xFF);
		out[2+pslen] = (byte)0;
		System.arraycopy(prefix, 0, out, 2+pslen+1, prefix.length);
		System.arraycopy(hash, 0, out, 2+pslen+1+prefix.length, hash.length);
		return out;
	}
}

