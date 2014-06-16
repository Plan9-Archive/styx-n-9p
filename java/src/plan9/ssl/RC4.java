package plan9.ssl;

// RC4 encryption
public class RC4 implements Encryption {
	byte[]	state;
	int	x, y;

	public	RC4(byte[] start){
		int p, index2;

		state = new byte[256];
		for(int sp = 0; sp < 256; sp++)
			state[sp] = (byte)sp;

		x = 0;
		y = 0;
		index2 = 0;
		p = 0;
		for(int sp = 0; sp < 256; sp++){
			byte t;
			t = state[sp];
			index2 = (start[p] + t + index2) & 255;
			state[sp] = state[index2];
			state[index2] = t;
			if(++p >= start.length)
				p = 0;
		}
	}

	// Encryption interface
	public void encrypt(byte[] buf, int offset, int len){
		int e = offset+len;
		for(int p = offset; p < e; p++){
			int tx, ty;
			x = (x+1)&255;
			tx = state[x] & 0xFF;
			y = (y+tx)&255;
			ty = state[y] & 0xFF;
			state[x] = (byte)ty;
			state[y] = (byte)tx;
			buf[p] ^= state[(tx+ty)&255];
		}
	}
	public void decrypt(byte[] buf, int offset, int len){
		encrypt(buf, offset, len);	// completely symmetric
	}
}
