package plan9.lib;

import java.lang.String;

import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.io.IOException;

/*
 * record-oriented messaging (on arbitrary transport) based on Inferno's msgio.m
 */

public class Msgio {
	final static int Maxmsg = 4096;
	final static int Hdrlen = 5;

	ByteChannel fd;
	ByteBuffer ib;
	ByteBuffer ob;

	public Msgio(ByteChannel fd){
		this.fd = fd;
		ib = ByteBuffer.allocate(Maxmsg);
		ob = ByteBuffer.allocate(Maxmsg+Hdrlen);
	}

	public final void sendmsg(byte[] data) throws IOException {
		if(data.length > Maxmsg)
			throw new IOException("message too long");
		ob.clear();
		ob.put(Strings.bytes(String.format("%04d", data.length)+"\n"));
		ob.put(data);
		ob.flip();
		fd.write(ob);
	}
	public final void sendmsg(String s) throws IOException {
		sendmsg(Strings.bytes(s));
	}

	public final void senderrmsg(String s) {
		try{
			byte[] a = Strings.bytes(s);
			int l = a.length;
			if(l > Maxmsg)
				l = Maxmsg;
			ob.clear();
			ob.put(Strings.bytes(String.format("!%03d", l)+"\n"));
			ob.put(a, 0, l);
			ob.flip();
			fd.write(ob);
		}catch(Exception e){}	// we don't care if it doesn't get there; we're done
	}
	public final byte[] getmsg() throws IOException, RemoteError {
		int i, n;

		if(!fillbuf(ib, Hdrlen))
			throw new IOException("remote hung up");	// was return null;
		if(ib.get(4) != (byte)'\n')
			throw new IOException("bad message syntax");
		boolean iserr = false;
		if(ib.get(0) == (byte)'!'){
			iserr = true;
			i = 1;
		}else
			i = 0;
		n = 0;
		for(; i < 4; i++){
			int c = ib.get(i)-'0';
			if(!(c >= 0 && c <= 9))
				throw new IOException("bad message syntax");
			n = n*10 + c;
		}
		if(n < 0 || n > Maxmsg)
			throw new IOException("bad message length");
		if(!fillbuf(ib, n))
			throw new IOException("remote hung up");
		if(iserr)
			throw new RemoteError(Strings.S(ib.array(), 0, n));
		byte a[] = new byte[n];
		ib.get(a);
		return a;
	}
	public final String gets() throws IOException, RemoteError {
		byte[] a = getmsg();
		return Strings.S(a);
	}
	private final boolean fillbuf(ByteBuffer b, int n) throws IOException {
		if(n > b.capacity())
			throw new IOException("message overlong");
		b.clear();
		b.limit(n);
		while(b.remaining() > 0 && fd.read(b) > 0){
			/* skip */
		}
		b.flip();
		if(b.remaining() == 0)
			return false;
		if(b.remaining() != n)
			throw new IOException("message truncated");
		return true;
	}
}

