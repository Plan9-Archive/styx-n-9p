package plan9.lib;

import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.ByteChannel;
import java.io.IOException;

// from styx-n-9p.googlecode.com (MIT licence)
public class Misc {

	public static final String dump(byte[] b, int i, int e, int max){
		if(max < 0)
			max = 64;
		if(e > b.length)
			e = b.length;
		StringBuilder bs = new StringBuilder(max);
		int n = 0;
		for(; i < e && ++n <= max; i++)
			bs.append(String.format("%02x", (int)b[i] & 0xFF));
		return bs.toString();
	}

	public static final String dump(byte[] b, int i, int e){
		return dump(b, i, e, -1);
	}

	public static final String dump(byte[] b, int max){
		return dump(b, 0, b.length, max);
	}

	public static final String dump(byte[] b){
		return dump(b, 0, b.length, b.length);
	}

	public static final String dump(ByteBuffer  b){
		StringBuilder bs = new StringBuilder(128);
		bs.append("buffer "+b.toString()+": ");
		int p = b.position();
		int n = 0;
		for(int i = p; i < b.limit() && ++n < 64; i++)
			bs.append(String.format("%02x", (int)b.get(i) & 0xFF));
		b.position(p);
		return bs.toString();
	}

	// read exactly a given number of bytes, returning a new buffer, or null on end-of-file
	public static final byte[] readn(ReadableByteChannel fd, int nb) throws IOException {
		byte[] buf = new byte[nb];
		for(int n = 0; n < nb;){
			int m = fd.read(ByteBuffer.wrap(buf, n, nb-n));
			if(m <= 0)
				return null;
			n += m;
		}
		return buf;
	}

	// read exactly a given number of bytes into an existing buffer at a given offset, returning the buffer, or null on end-of-file
	public static final byte[] readn(ReadableByteChannel fd, byte[] buf, int offset, int nb) throws IOException {
		for(int n = 0; n < nb;){
			int m = fd.read(ByteBuffer.wrap(buf, offset+n, nb-n));
			if(m <= 0)
				return null;
			n += m;
		}
		return buf;
	}

	// read exactly a given number of bytes into an existing buffer, returning the buffer, or null on end-of-file
	public static final byte[] readn(ReadableByteChannel fd, byte[] buf, int nb) throws IOException {
		return readn(fd, buf, 0, nb);
	}

	// give a Thread a better name than the JVM manages
	public static void nominate(Thread t){
		t.setName(String.format("%s id#%d", t.getClass().getName(), t.getId()));
	}

	// ensure an fd is closed, never mind what happens: we're done with it
	public static void qclose(ByteChannel fd){
		if(fd != null){
			try{
				fd.close();
			}catch(Exception e){
				// we don't care, as long as it's gone
			}
		}
	}
}
