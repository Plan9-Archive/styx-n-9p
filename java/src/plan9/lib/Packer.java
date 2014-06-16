package plan9.lib;

// from styx-n-9p.googlecode.com, MIT licence

import java.lang.*;
import java.util.Arrays;
import java.nio.ByteBuffer;

public class Packer {

	byte[]	data;
	int	o0;	// initial offset
	int	o;

	public Packer(int n){
		o = o0 = 0;
		data = new byte[n];
	}
	public Packer(byte[] a){
		o = o0 = 0;
		data = a;
	}
	public Packer(byte[] a, int offset){
		o = o0 = offset;
		data = a;
	}
	public void restart(){
		o = o0;
	}
	public int length(){
		return o-o0;
	}
	public ByteBuffer buffer(){
		return ByteBuffer.wrap(data, o0, length());
	}
	public byte[] array(){
		return data;
	}
	public int offset(){
		return o;
	}

	public byte get(){
		return data[o++];
	}
	public int get1(){
		return (int)data[o++] & 0xFF;
	}
	public int get2(){
		int v;
		v = (int)data[o+0] & 0xFF;
		v |= ((int)data[o+1] & 0xFF)<<8;
		o += 2;
		return v;
	}
	public int get4(){
		int v;

		v = (int)data[o+0] & 0xFF;
		v |= ((int)data[o+1] & 0xFF)<<8;
		v |= ((int)data[o+2] & 0xFF)<<16;
		v |= ((int)data[o+3] & 0xFF)<<24;
		o += 4;
		return v;
	}
	public long get8(){
		long n0 = (long)get4() & 0xFFFFFFFFL;
		return ((long)get4() << 32) | n0;
	}
	public byte[] geta(int n){
		byte[] a = new byte[n];
		System.arraycopy(data, o, a, 0, n);
		o += n;
		return a;
	}

	public final void put(byte b){
		data[o++] = b;
	}
	public final void put1(int v){
		data[o++] = (byte)(v & 0xFF);
	}
	public final void put2(int v){
		data[o+0] = (byte)(v);
		data[o+1] = (byte)(v>>8);
		o += 2;
	}
	public final void put4(int v){
		data[o+0] = (byte)v;
		data[o+1] = (byte)(v>>8);
		data[o+2] = (byte)(v>>16);
		data[o+3] = (byte)(v>>24);
		o += 4;
	}
	public final void put8(long v){
		data[o+0] = (byte)v;
		data[o+1] = (byte)(v>>8);
		data[o+2] = (byte)(v>>16);
		data[o+3] = (byte)(v>>24);
		data[o+4] = (byte)(v>>32);
		data[o+5] = (byte)(v>>40);
		data[o+6] = (byte)(v>>48);
		data[o+7] = (byte)(v>>56);
		o += 8;
	}

	public final void puta(byte[] a, int n){
		if(a != null && a.length != 0){
			int l = a.length < n? a.length: n;
			System.arraycopy(a, 0, data, o, l);
			o += l;
			n -= l;
		}
		if(n > 0){
			Arrays.fill(data, o, o+n, (byte)0);
			o += n;
		}
	}
	public final void puta(byte[] a){	// a must not be null
		puta(a, a.length);
	}

	public final String gets(int n){	// fixed-length string with null byte
		try{
			int o1 = o;
			o += n;
			if(n > 0)
				n--;	// must have null byte
			for(int i = 0; i < n; i++){
				if(data[o1+i] == (byte)0){
					n = i;
					break;
				}
			}
			return new String(data, o1, n, "UTF-8");
		}catch(java.io.UnsupportedEncodingException e){
			return "Egosling";
		}
	}

	public final void puts(String s){	// string with explicit count
		if(s == null || s.length() == 0){
			put2(0);
			return;
		}
		byte[] a = Strings.bytes(s);
		put2(a.length);
		puta(a, a.length);
	}

	public final void puts(String s, int n) {	// string as fixed array
		puta(Strings.bytes(s), n);
	}
}
