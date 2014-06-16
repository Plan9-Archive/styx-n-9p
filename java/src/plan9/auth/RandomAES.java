package plan9.auth;

import java.util.Arrays;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.NoSuchPaddingException;

public class RandomAES implements Random {

	private static final int AESbsize = 128/8;	// block size in bytes

	private byte[]	counter = new byte[AESbsize];
	private Cipher	cipher;
	private byte[]	data;
	private int offset;

	private static class AESKey implements Key {
		byte[]	key;

		AESKey(byte[] a){
			key = Arrays.copyOf(a, a.length);
		}
		public byte[] getEncoded(){
			return Arrays.copyOf(key, key.length);
		}
		public String getAlgorithm(){
			return "AES";
		}
		public String getFormat(){
			return "RAW";
		}
	};

	private static final void inc(byte[] a){
		for(int i = 0; i < a.length; i++)
			if(++a[i] == 0)
				break;
	}

	public RandomAES() throws GeneralSecurityException {
		byte[] seed = new byte[AESbsize];
		Aids.memrandom(seed, 0, seed.length);
		cipher = Cipher.getInstance("AES/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, new AESKey(seed));
		offset = AESbsize;
	}

	public synchronized void randombytes(byte[] a, int o, int n){
		for(int i = 0; i < n;){
			int avail = AESbsize - offset;
			if(data == null || avail == 0){
				inc(counter);
				try{
					data = cipher.doFinal(counter);
				}catch(GeneralSecurityException e){
					throw new RuntimeException("impossible failure in memrandom", e);
				}
				offset = 0;
				avail = AESbsize;
			}
			int l = n - i;
			if(l > avail)
				l = avail;
			System.arraycopy(data, offset, a, o+i, avail);
			offset += avail;
			n -= avail;
		}
	}
}
