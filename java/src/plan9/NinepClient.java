package plan9;

/*
 * 9P2000 client
 * (a renaming of the StyxClient of styx-n-9p.googlecode.com)
 *
 *
 * TO DO
 *	full walk (chunks of MAXWELEM, ..)
 *
 * Copyright © 2005 Vita Nuova Holdings Limited [C H Forsyth, forsyth@vitanuova.com]
 * Subject to the terms of the MIT-template (google for a copy)
 */

import java.nio.ByteBuffer;	// not ideal, but will do for now
import java.nio.channels.Channel;
import java.nio.channels.ByteChannel;
import java.util.StringTokenizer;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.AsynchronousCloseException;

import static plan9.Ninep.*;

import plan9.lib.Misc;
import plan9.lib.Strings;

/**
 * NinepClient provides application-level access to a set of 9P servers, each accessed over a separate ByteChannel connection.
 * An instance of NinepClient provides state for a set of 9P connections.
 * Each 9P connection is represented by an instance of the inner class <i>Conn</i> ({@link NinepClient.Conn}),
 * associated with a ByteChannel connected to its server. Each 9P server has one or more named file systems,
 * including a default file system (named by the empty string).
 * <p>
 * A client <i>attaches</i> to one of those file systems.
 * If the server requires authentication, that <i>attach</i> request must be preceded by a
 * conversation on an authentication file (or "auth file") that establishes permission to request the attach.
 * A special <i>auth</i> request creates a new auth file. (The "file" is virtual and anonymous.)
 * If the server does not demand authentication, it will refuse an attempt to create an auth file. The usual
 * sequence is to attempt an <i>auth</i>, authenticate on the resulting auth file if it succeeds,
 * then <i>attach</i> after successful authentication but if the <i>auth</i> fails,
 * to attempt the <i>attach</i> anyway, without authentication.
 * (If the <i>auth</i> succeeds, but the conversation on the auth file fails, the <i>attach</i> will not succeed.)
 * For example, the class <i>NinepImport</i>, which encapsulates importing a file system exported by a 9P cpu server,
 * also encapsulates the <i>auth</i>-authentication-<i>attach</i> sequence in its simple <i>attach</i> operation.
 * <p>
 * The result of a successful attach is an instance of the inner class <i>FS</i> ({@link NinepClient.FS}), which provides file-system level
 * operations, including open, create, stat, wstat, and remove. The open and create operations return an instance
 * of the <i>FD</i> inner class ({@link NinepClient.FD}), allowing IO to a named file, compatible with the <i>ByteChannel</i> interface,
 * with extensions to support 9P's stat and wstat operations.
 */
public class NinepClient {

	/** open for read */
	public static final int	OREAD = 0; 	

	/** open for write */
	public static final int	OWRITE = 1; 	

	/** open for read and write */
	public static final int	ORDWR = 2; 	

	/** open for execute, == read but check execute permission */
	public static final int	OEXEC = 3; 	

	/** OR'ed in to open mode: truncate file first */
	public static final int	OTRUNC = 16; 	

	/** OR'ed in to open mode: remove on close */
	public static final int	ORCLOSE = 64; 

	/** OR'ed in to open mode: exclusive-create */
	public static final int OEXCL = 0x1000;

	/** The offset in seek is an absolute offset from the start of the file */
	static public final int SEEKSTART = 0;

	/** The offset in seek is a signed offset relative to the current file position */
	static public final int SEEKRELA = 1;

	/** The offset in seek is a signed offset relative to the length of the file (ie, end of file) */
	static public final int SEEKEND = 2;

	static public final String Enomem = "out of memory";
	static public final String Eexists = "file already exists";
	static public final String Eisdir = "file is a directory";
	static public final String Enegoff = "negative i/o offset";
	static public final String Etoosmall = "read or write too small";
	static public final String Ebadusefd = "inappropriate use of fd";
	static public final String Ehungup = "i/o on hungup channel";
	static public final String Eversion = "version not established for mount channel";
	static public final String Eintr = "interrupted";
	static public final String Enotdir = "not a directory";
	static public final String Edoesnotexist = "does not exist";
	static public final String Emountrpc = "mount rpc error";

	private static ThreadLocal<String> lasterror = new ThreadLocal<String>();

	/**
	 * Return the per-thread error string, which gives the error text from the most recent error.
	 */
	public final static String errstr() { return lasterror.get(); }

	/**
	 * Set the per-thread error string.
	 */
	public final static void werrstr(String s) { lasterror.set(s); }

	final static void ioerror(String s) throws InterruptedIOException, IOException {
		lasterror.set(s);
		if(s != null && s.equals(Eintr))
			throw new InterruptedIOException(s);
		throw new IOException(s);
	}
	final static void ioerror() throws IOException {
		ioerror(errstr());
	}

	private static Ninep ninep = new Ninep();

	private static Log log = LogFactory.logger(NinepClient.class);

	static String where(){
		String s = "";
		for(StackTraceElement e: Thread.currentThread().getStackTrace())
			s += e + "\n";
		return s;
	}

	/**
	 * Create a new 9P client instance.
	 * Given a NinepClient, the next step is to create a Conn, establishing a 9P connection on a given ByteChannel.
	 * Conn, FS, and FD do all the real work.
	 */
	public NinepClient(){
		settag(0);
		settag(Ninep.NOTAG);
	}

	private static class Request {
		Ninep.Tmsg	t;
		Ninep.Rmsg	r;
		Request	flushed;
		long	timeout;

		Request(Ninep.Tmsg t){ this.t = t; timeout = 0; }
		Request(Ninep.Tmsg t, Request old){ this.t = t; this.flushed = old; timeout = old.timeout; }

		void timelimit(long ms){ timeout = ms; }

		synchronized final void awaitreply() throws InterruptedException {
			if(timeout == 0){
				while(r == null)
					this.wait();
			}else{
				long t0 = System.currentTimeMillis();
				while(r == null){
					this.wait(timeout);
					if(r != null)
						break;
					if(t0+timeout < System.currentTimeMillis())
						throw new InterruptedException("file system operation timed-out");
				}
			}
		}

		synchronized final void replied(Ninep.Rmsg reply){
			if(this.t instanceof Ninep.Tflush && reply instanceof Ninep.Rerror)
				reply = ninep.new Rflush(reply.tag);	// must not Rerror a Tflush
			this.r = reply;
			this.notify();
			if(false && log.tracing())
				log.trace("notify: %d %s %s", t.tag, t.mname(), reply.mname());
		}

		synchronized final void replyerr(String why, boolean hangup){
			Ninep.Rmsg reply;

			if(this.t instanceof Ninep.Tflush)
				reply = ninep.new Rflush(this.t.tag);	// must not Rerror a Tflush
			else
				reply = ninep.new Rerror(this.t.tag, why, hangup);
			this.r = reply;
			this.notify();
		}

		final void replyerr(String why){
			replyerr(why, false);
		}
	}

	static class ReqEl {
		ReqEl	next;
		Request	r;
			ReqEl(Request r, ReqEl next){
				this.r = r; this.next = next;
			}
	}

	static class RQ {
		ReqEl	qh;
		ReqEl	qt;
		String	err;

		synchronized Request get() throws InterruptedException {
			ReqEl el;

			while((el = qh) == null && err == null)
				wait();
			if(err != null)
				throw new InterruptedException(Eintr);
			qh = el.next;
			return el.r;
		}
		synchronized void put(Request r) throws InterruptedIOException, IOException {
			if(err != null)
				ioerror(err);
			ReqEl el = new ReqEl(r, null);
			if(qh == null){
				qh = el;
				notify();
			}else
				qt.next = el;
			qt = el;
		}
		synchronized void poison(String reason){
			ReqEl el;

			if(err == null)
				err = reason;
			for(; (el = qh) != null; qh = el.next)
				el.r.replyerr(err, true);
		}
	}

	// record a set of outstanding Requests, in order to ensure replying to flushes in correct order on error
	private static class Requests {
		ReqEl	set;	// set of requests; tags are unique
		String	err;	// !=null: fail incoming requests with this error

		// add a new Request; ordering is unimportant
		synchronized final void add(Request req){
			if(err == null)
				set = new ReqEl(req, set);
			else
				req.replied(ninep.new Rerror(req.t.tag, err, true));
		}

		// find the Request corresponding to r's tag, and mark it done, notifying its author, and freeing the tag
		final void completed(Ninep.Rmsg r){
			ReqEl el, prev;
			synchronized(this){
				prev = null;
				for(el = set; el != null; el = el.next){
					if(el.r.t.tag == r.tag){
						if(prev != null)
							prev.next = el.next;
						else
							set = el.next;
						puttag(r.tag);
						el.r.replied(r);
						return;
					}
					prev = el;
				}
			}
			log.warn("unexpected reply tag %d type %d (%s)", r.tag, r.mtype(), r.mname());
			//System.out.print("TAG: "+where());
		}
		final void diagnose(String why){
			log.warn("Ninep message error: "+why);
		}

		// shut down the channel, with reason, forcing all pending requests to fail, and answering flushes
		final void shutdown(String why){
			if(log.debugging())
				log.debug("shut down: "+why);
			synchronized(this){
				if(err == null)	// first error might be most accurate
					err = why;
				ReqEl el;
				while((el = set) != null){
					set = el.next;
					el.r.replyerr(err, true);
				}
			}
		}
	}

	// thanks to Java's ByteChannel, which allows close to be repeated, we can't recycle fids just by recycling FDs
	// because there isn't any operation to mark a ByteChannel as no longer used
	// instead, separate Fid and FD
	private static class Fid {
		int	fid;
		int	inuse;
		Fid	next;

		Fid(int v){
			this.fid = v;
			this.inuse = 1;
			this.next = null;
		}

		synchronized Fid	incref(){
			inuse++;
			return this;
		}

		synchronized int	decref(){
			return --inuse;
		}

		synchronized boolean isfree(){
			return inuse == 0;
		}
	}

	// recycle fids by recycling FDs
	private static class Fids {
		Fid	avail;
		int	fidgen = 0;
		int	inuse = 0;
		boolean	closing = false;

		synchronized Fid alloc() {
			Fid f;
			f = avail;
			if(f != null){
				avail = f.next;
				f.next = null;
				f.inuse = 1;
			}else
				f = new Fid(++fidgen);
			inuse++;
			return f;
		}

		synchronized void free(Fid f) {
			if(f != null && f.isfree()){
				f.next = avail;
				avail = f;
				inuse--;
			}
		}

		synchronized boolean close(){
			if(inuse != 0){
				closing = true;
				return false;
			}
			closing = false;
			return true;
		}

		synchronized boolean shouldclose(){
			return inuse == 0 && closing;
		}
	}

	/**
	 * Conn represents a 9P connection on a given ByteChannel.
	 * <p>
	 * It provides operations to initialise the connection (version), obtain an authentication file (auth),
	 * attach to the root of a file system offered by the server (attach), and close the connection (close).
	 * <p>
	 * A successful attach returns an FS instance allowing operations on files by name.
	 * Two of those operations, create and open, return an FD instance allowing IO on files.
	 * Conn's auth operation also returns an FD instance, allowing IO on the resulting authentication file.
	 * <p>
	 * None of the operations regard failure as exceptional, and therefore do not throw exceptions.
	 * Instead they return an error value suitable for the normal return type of the function.
	 * A per-thread error string contains text giving the diagnostic for the most recent error.
	 * The function errstr returns the error string.
	 */
	public class Conn {
		ByteChannel	fd;
		int	msize = 0;

		RQ	writeq = new RQ();	// waiting to be sent to server
		Requests	active = new Requests();	// sent to server; waiting for reply
		Fids		fids = new Fids();

		Object	versioning = new Object();	// Tversion queue lock
		String	versioned;

		boolean asyncflush = false;
		boolean closed = false;
		long	optimer = 0;

		public Conn(ByteChannel fd){
			this.fd = fd;
			(new Writer()).start();
			(new Reader()).start();
		}

		/**
		 * Return the per-thread error string, which gives the error text from the most recent error.
		 */
		public String errstr(){
			return NinepClient.this.errstr();
		}

		/**
		 * Set time limit in milliseconds for each 9P operation, until reset to zero.
		 */
		public void setTimeLimit(long ms){
			optimer = ms;
		}

		/**
		 * Optionally specify a maximum message size and protocol version.
		 * By default, the protocol will use messages no larger than Ninep.MAXRPC, and negotiate the version "9P2000".
		 * The 9P server can negotiate a message size limit that is still smaller.
		 * <p>
		 * Version does a 9P Tversion transaction.
		 *	@param	msize	desired maximum message size in bytes (if 0, use default Ninep.MAXRPC)
		 *	@param	v		desired protocol version (if null, use Ninep.VERSION, which is "9P2000")
		 *	@return	protocol version negotiated, or null if the negotiation failed (see the error string)
		 *	@throws	InterruptedIOException	operation was interrupted (eg, by an alarm)
		 *	@throws	ConnectionFailed	9P connection was shut down, by hangup or IO error
		 */
		public String version(int msize, String v) throws ConnectionFailed, InterruptedIOException {
			if(msize == 0)
				msize = Ninep.MAXRPC;
			if(v == null)
				v = Ninep.VERSION;
			synchronized(versioning){	// only one Tversion active at once on a connection
				if(versioned != null)
					return versioned;	// already done; TO DO: check compatibility
				Ninep.Rversion r = (Ninep.Rversion)ninepreq(ninep.new Tversion(msize, v));
				if(r == null)
					return null;
				// check compatibility
				if(r.msize < 256 || r.msize > 1024*1024){
					werrstr("nonsense value of remote msize in version");
					return null;
				}
				if(r.msize > msize){
					werrstr("server tries to increase msize in version");
					return null;
				}
				int n = r.version.length();
				if(!v.substring(0, n).equals(r.version)){
					werrstr("bad 9P version received from server");
					return null;
				}
				this.msize = r.msize;
				this.versioned = r.version;
			}
			return this.versioned;
		}

		/**
		 * Return a FD (file descriptor) that represents a channel to the authentication system on the server.
		 * If the server requires authentication, a successful auth will return an FD instance that allows an
		 * auth file on the server to be read and written to exchange authentication data with the server.
		 * The aim is to authenticate <i>uname</i>'s access to the server's tree <i>aname</i>.
		 *<p>
		 * If the server does not require authentication, it will reply with an error, and auth will return null.
		 * That does not represent a failure to authenticate, but rather that authentication is not required.
		 *	@param	uname	user name that will authenticate
		 *	@param	aname	name of server tree; use "" or null to get the default (main) tree
		 *	@return	an FD instance connected to an authentication file; returns null if the server does not require authentication
		 *	@throws	InterruptedIOException	operation was interrupted (eg, by an alarm)
		 *	@throws	ConnectionFailed	9P connection was shut down, by hangup or IO error
		 */
		public FD auth(String uname, String aname) throws ConnectionFailed, InterruptedIOException {
			if(versioned == null && version(0, null) == null)
				return null;
			FD fd = newfd();
			Ninep.Rauth r = (Ninep.Rauth)ninepreq(ninep.new Tauth(fd.fid, uname, aname));
			if(r == null){
				fd.free();
				return null;
			}
			fd.qid = r.aqid;
			fd.mode = Ninep.ORDWR;
			return fd;
		}

		/**
		 * Attach as user <i>uname</i> to the root of the server's tree <i>aname</i>.
		 * Return an FS instance giving access to that tree.
		 * If the server does not require authentication, <i>afd</i> should be null.
		 * If the server does require authentication, <i>afd</i> must be the result of a previous
		 * <i>auth</i> call specifying the same <i>uname</i> and <i>aname</i>,
		 * over which an authentication protocol has been run successfully.
		 *	@param	afd	file descriptor for authentication file, or null if none is needed
		 *	@param	uname	user name accessing the file system
		 *	@param	aname	access the tree with the given name (null or "" for default tree)
		 *	@throws	InterruptedIOException	operation was interrupted (eg, by an alarm)
		 *	@throws	ConnectionFailed	9P connection was shut down, by hangup or IO error
		 */
		public FS attach(FD afd, String uname, String aname) throws ConnectionFailed, InterruptedIOException {
			if(versioned == null && version(0, null) == null)
				return null;
			FD fd = newfd();
			int afid = Ninep.NOFID;
			if(afd != null)
				afid = afd.fid;
			Ninep.Rattach r = (Ninep.Rattach)ninepreq(ninep.new Tattach(fd.fid, afid, uname, aname));
			if(r == null){
				fd.free();
				return null;
			}
			fd.name = "/";
			fd.qid = r.qid;
			return new FS(this, fd);
		}

		/** On an interrupt, send flush and wait for the reply */
		synchronized public void waitflush(){
			asyncflush = false;
		}

		/** On an interrupt, send flush but do not wait for the reply */
		synchronized public void quickflush(){
			asyncflush = true;
		}

		synchronized boolean isasyncflush(){
			return asyncflush;
		}

		/** Close the 9P connection as soon as its FS and FD instances have all been closed. */
		synchronized public void close(){
			if(!closed){
				if(fids == null)
					return;	// already done
				if(!fids.close())
					return;	// still in use
				fids = null;
			}
			shutdown();
		}

		/** Shut down the 9P connection abruptly, on error */
		synchronized public void shutdown(){
			if(!closed){
				closed = true;
				try{
					writeq.put(null);	// shut down Writer
				}catch(IOException e){
					// already dead
				}
				try{
					fd.close();	// will have important side-effect of stopping Reader
				}catch(IOException e){
					// we don't care
				}
				if(log.tracing())
					log.trace("9P channel closed");
			}
		}

		void interrupted() throws InterruptedIOException {
			werrstr(Eintr);
			throw new InterruptedIOException(Eintr);
		}

		protected Ninep.Rmsg ninepreq(Ninep.Tmsg f) throws ConnectionFailed, InterruptedIOException {
			int otype = f.mtype();
			Request req = new Request(f);
			boolean flushing = false;
			if(optimer != 0)
				req.timelimit(optimer);
		Work:
			for(;;){
				try{
					/* channel must not be non-blocking (short writes) */
					writeq.put(req);
					if(flushing && isasyncflush())
						interrupted();
					req.awaitreply();
					break Work;
				}catch(InterruptedException e){
					if(f.tag == Ninep.NOTAG){
						werrstr("9P version request interrupted");
						throw new InterruptedIOException(errstr());
					}
					if(log.tracing())
						log.trace("interrupt: flush %s", req.t);
					req = new Request(ninep.new Tflush(f.tag), req);	// ie, flush original request, not last Tflush
					flushing = true;
				}catch(InterruptedIOException e){
					throw e;	// just pass it on, can only be asyncflush
				}catch(IOException e){	// anything else is fatal
					flushout(req);
					werrstr("i/o error: "+e);
					active.shutdown(errstr());
					throw new ConnectionFailed(errstr(), e);
				}
			}
			if(log.tracing())
				log.trace("rcvd reply "+req.r);
			if(req.flushed != null){
				flushout(req);
				interrupted();
			}
			Ninep.Rmsg r = req.r;
			if(r instanceof Ninep.Rerror){
				Ninep.Rerror re = (Ninep.Rerror)r;
				werrstr(re.ename);
				if(re.hangup)
					throw new ConnectionFailed(errstr());
				return null;
			}
			if(r instanceof Ninep.Rflush)
				interrupted();
			if(r.mtype() != otype+1){
				log.warn("unexpected reply: tag %d type %d(%s) otag %d otype %d", r.tag, r.mtype(), r.mname(), f.tag, otype);
				werrstr("mismatched 9P reply");
				return null;
			}
			return r;
		}

		// dispose of unanswered messages in a chain of flushes
		private void flushout(Request req){
			// we can't lock req because active.completed might do so indirectly via replied, but it
			// doesn't matter, because the current process is the only one working with req.flushed
			for(;;){
				if(req.r == null){
					// build flush request with tag matching original request
					Ninep.Rmsg flush = ninep.new Rflush(req.t.tag);
					active.completed(flush);
				}
				if(req.flushed == null)
					break;
				req = req.flushed;
			}
		}

		protected final FD newfd(){
			if(fids == null)
				throw new RuntimeException("programming error: NinepClient used after shutdown");
			return new FD(this, fids.alloc());
		}
		protected final void freefid(Fid fidp){
			if(fidp != null){
				fids.free(fidp);
				if(fids.shouldclose())
					close();
			}
		}

		/*
		 *	Java forces a daemon process for Channel I/O in both directions to allow
		 *	waiting requests to be interrupted. An InterruptableChannel exists,
		 *	but cannot be associated with old java.io, and furthermore, poisons
		 *	the channel on the interrupt!
		 */

		private class Reader extends Thread {
			Reader(){
				setDaemon(true);
				Misc.nominate(this);
			}
			private final void fillbuf(ByteChannel fd, ByteBuffer b) throws IOException {
				while(b.remaining() > 0 && fd.read(b) > 0){
					/* skip */
				}
				b.flip();
				if(b.remaining() != b.capacity())
					throw new IOException("Ninep message truncated");
			}
			public final void run(){
				try{
					Ninep.Unpack unpacker = ninep.new Unpack();
					ByteBuffer sizeb = ByteBuffer.allocate(Ninep.BIT32SZ);
					for(;;){
						int msglim = msize;
						if(msglim == 0)
							msglim = Ninep.MAXRPC;
						fillbuf(fd, sizeb);
						int ml = (int)sizeb.get() & 0xFF;
						ml |= ((int)sizeb.get() & 0xFF) << 8;
						ml |= ((int)sizeb.get() & 0xFF) << 16;
						ml |= ((int)sizeb.get() & 0xFF) << 24;
						sizeb.clear();
						if(ml > msglim){
							active.shutdown(String.format("9P message longer than agreed: %d > %d [%s ...]", ml, msglim));
							return;
						}
						if((ml -= Ninep.BIT32SZ) <= 0){
							active.shutdown("invalid 9P message size");
							return;
						}
						ByteBuffer b = ByteBuffer.allocate(ml);
						fillbuf(fd, b);
						try{
							Ninep.Rmsg r = unpacker.unpackR(b);
							if(log.tracing())
								log.trace("<- %s", r);
							active.completed(r);
						}catch(Ninep.FormatError e){
							active.diagnose("can't unpack: bad 9P type or format");
						}
					}
				}catch(EOFException e){
					active.shutdown(Ehungup);
				}catch(ClosedChannelException e){
					active.shutdown(Ehungup);
				}catch(IOException e){
					active.shutdown("error reading 9P message: "+e);
				}
			}
		}

		ByteBuffer packmsg(Ninep.Tmsg f) throws IOException {
			int otype = f.mtype();
			int tag;
			if(otype == Ninep.MTversion)
				f.tag = Ninep.NOTAG;
			else if((tag = gettag()) != Ninep.NOTAG)
				f.tag = tag;
			else
				throw new IOException("out of 9P message tags");	// unlikely: there are 2^16-2
			int size = f.packedsize();
			ByteBuffer buf = ByteBuffer.allocate(size);
			f.packsize(buf, size);
			f.pack(buf);
			buf.flip();
			return buf;
		}

		// could have more than one of these, if it's a bottleneck
		private class Writer extends Thread {
			Writer(){
				setDaemon(true);
				Misc.nominate(this);
			}

			public final void run(){
				/* we rely on Channel's non-interleaving semantics (TO DO: test) */
				/* channel must not be non-blocking (short writes) */
				String err;
			   Service:
				for(;;){
					Request req;
					err = Ehungup;
					try{
						req = writeq.get();
						if(req == null)
							break Service;
					}catch(InterruptedException e){
						break Service;
					}
					ByteBuffer buf = null;
					try{
						buf = packmsg(req.t);
					}catch(IOException e){
						log.trace("pack: "+req.t+": exception: "+e);
						req.replyerr("error packing 9P request: "+e.getMessage());
						continue;
					}
					try{
						if(log.tracing())
							log.trace("-> %s", req.t);
						active.add(req);	// must add before write, to avoid race with reply
						int size = buf.remaining();
						if(fd.write(buf) != size)
							throw new IOException("short write on 9P channel");
					}catch(AsynchronousCloseException e){
						req.replyerr(err);
						break Service;
					}catch(ClosedChannelException e){
						req.replyerr(err);
						break Service;
					}catch(IOException e){
						err = Emountrpc+": "+e.getMessage();
						req.replyerr(err);
						// attempt to continue, as devmnt does
					}
				}
				writeq.poison(err);
				if(log.tracing())
					log.trace("Writer exit: "+err);
			}
		}
	}

	/**
	 * FS represents an attached file system (file tree) on a 9P connection.
	 * <p>
	 * It provides operations to access and change the file system using hierarchical names, including
	 * create, open, stat, wstat, remove, chdir and getwd. All but chdir and getwd apply to all file types including directories;
	 * chdir and getwd are restricted to directories.
	 *
	 * By convention, these operations do not consider failure to be exceptional, and do not throw exceptions.
	 * Instead, an error value is returned, appropriate for the operations return type.
	 * Errstr returns the cause of the last error, as a string. Usually it will be the error text returned by the 9P server,
	 * although a few errors are diagnosed locally.
	 * <p>
	 * Create and open access named files for IO, returning instances of the class FD.
	 */
	public class FS {
		int	inuse = 1;
		Conn	conn;
		FD	root;
		private ThreadLocal<FD> dot;

		private final FD getdot(){ return dot.get(); }
		private final void setdot(FD fd){
			FD ofd = getdot();
			dot.set(fd);
			if(ofd != null)
				ofd.close();
		}

		protected FS(Conn conn, FD root){
			this.conn = conn;
			this.root = root;
			this.dot = new ThreadLocal<FD>();
		}

		/** Return the per-thread error string */
		public String errstr(){
			return NinepClient.this.errstr();
		}

		/** @deprecated */
		public FS use(){
			synchronized(this){
				inuse++;
			}
			return this;
		}

		/**
		 * Close this file system instance (ie, detach).
		 * Close (clunk) the root and current directories.
		 * <p>
		 * The underlying connection will be closed after all open files and all other file systems currently using the connection have been closed.
		 */
		public void close(){		// TO DO: unmount as better name?
			synchronized(this){
				if(--inuse != 0)
					return;
			}
			root.close();
			root = null;
			FD fd = getdot();
			if(fd != null){
				fd.close();
				fd = null;
			}
			conn.close();
		}

		/**
		 * Open the file <i>name</i> with the given open <i>mode</i> (eg, Ninep.OREAD, NInep.OWRITE, or Ninep.ORDWR), and return a {@link NinepClient.FD} for subsequent file IO.
		 *	@return a {@link NinepClient.FD} value for IO, or null if the file could not be opened (the error string gives the reason)
		 *	@throws	InterruptedIOException	operation was interrupted (eg, by an alarm)
		 *	@throws	ConnectionFailed	9P connection was shut down, by hangup or IO error
		 */
		public FD open(String name, int mode) throws ConnectionFailed, InterruptedIOException {
			FD fd = walk(name);
			if(fd == null)
				return null;
			Ninep.Ropen r = (Ninep.Ropen)conn.ninepreq(ninep.new Topen(fd.fid, mode));
			if(r == null){
				fd.close();
				return null;
			}
			fd.open(openmode(mode), r.iounit, r.qid);
			return fd;
		}

		/**
		 * Create the file <i>name</i> if it does not exist, or truncate it if it does, then open with the given open <i>mode</i> (eg, Ninep.OREAD, NInep.OWRITE, or Ninep.ORDWR), and return a {@link NinepClient.FD} for subsequent file IO.
		 * If the file had to be created, its permissions are set to <i>perm</i>. If the file already exists, <i>perm</i> is ignored.
		 *	@return a {@link NinepClient.FD} value for IO, or null if the file could not be opened (the error string gives the reason)
		 *	@throws	InterruptedIOException	operation was interrupted (eg, by an alarm)
		 *	@throws	ConnectionFailed	9P connection was shut down, by hangup or IO error
		 */
		public FD create(String name, int mode, int perm) throws ConnectionFailed, InterruptedIOException {
			Parse p = new Parse(name);
			if(p.els.length == 0){
				werrstr(Eexists);
				return null;
			}
			FD fd = conn.newfd();
			if(!walk(walkfrom(p), fd, new Parse(p, 0, p.els.length-1))){	// walk to penultimate entry
				fd.free();
				return null;
			}
			/* try to walk to final entry */
			switch(opentrunc(fd, p, mode)){
			case -1:
				fd.close();
				return null;
			case 1:
				return fd;
			}
			/* must create */
			String entry = p.els[p.els.length-1];
			Ninep.Rcreate r = (Ninep.Rcreate)conn.ninepreq(ninep.new Tcreate(fd.fid, entry, perm, mode));
			if(r != null){
				fd.name = addname(fd.name, entry);
				fd.mode = openmode(mode);
				fd.iounit = r.iounit;
				fd.qid = r.qid;
				return fd;
			}
			/* to allow for create/create race, attempt a second open here */
			String s = errstr();
			if(opentrunc(fd, p, mode) <= 0){
				fd.close();
				werrstr(s);	/* restore original diagnostic */
				return null;
			}
			return fd;
		}

		/**
		 * Return the directory information for the named file, or null if an error occurred (setting the error string).
		 *	@throws	InterruptedIOException	operation was interrupted (eg, by an alarm)
		 *	@throws	ConnectionFailed	9P connection was shut down, by hangup or IO error
		 */
		public Dir stat(String name) throws ConnectionFailed, InterruptedIOException {
			FD fd = walk(name);
			if(fd == null)
				return null;
			Dir d = fd.qstat();
			fd.close();
			return d;
		}

		/**
		 * Update the directory information for the named file, returning true iff the update succeeded.
		 * The <i>Dir</i> parameter has a special form: values that should not change will either be the
		 * file's original values, or special "don't care" values, described in <i>stat</i>(5), typically null or
		 * empty strings for string values, and ~0 for integer values. Any other values will change the file's
		 * directory entry to match. If the request is rejected, <i>wstat</i> returns false and updates the error string.
		 * @param	d	A <i>Dir</i> instance containing the values to update
		 * @return	true iff the file server accepted the update
		 *	@throws	InterruptedIOException	operation was interrupted (eg, by an alarm)
		 *	@throws	ConnectionFailed	9P connection was shut down, by hangup or IO error
		 */
		public boolean wstat(String name, Dir d) throws ConnectionFailed, InterruptedIOException {
			FD fd = walk(name);
			if(fd == null)
				return false;
			boolean r = fd.wstat(d);
			fd.close();
			return r;
		}

		/**
		 * Remove the named file, returning true if it was successfully removed, and false on error (setting the error string).
		 *	@throws	InterruptedIOException	operation was interrupted (eg, by an alarm)
		 *	@throws	ConnectionFailed	9P connection was shut down, by hangup or IO error
		 */
		public boolean remove(String name) throws ConnectionFailed, InterruptedIOException {
			FD fd = walk(name);
			if(fd == null)
				return false;
			Ninep.Rremove r = (Ninep.Rremove)conn.ninepreq(ninep.new Tremove(fd.fid));
			fd.close();
			return r != null;
		}

		/**
		  * Set the current directory to the named directory, returning true on success, and false on any error (eg, doesn't exist, not a directory), setting the error string
		 *	@throws	InterruptedIOException	operation was interrupted (eg, by an alarm)
		 *	@throws	ConnectionFailed	9P connection was shut down, by hangup or IO error
		 */
		public boolean chdir(String name) throws ConnectionFailed, InterruptedIOException {
			if(name == null){
				setdot(null);
				return true;
			}
			FD fd = walk(name);
			if(fd == null)
				return false;
			setdot(fd);
			return true;
		}

		/** Return the name of the current directory */
		public String getwd(){
			FD fd = getdot();
			if(fd == null)
				return root.name;
			return fd.name;
		}

		/* implementation */

		protected class Parse {
			String	name;
			String[]	els;
			boolean	abs;

			Parse(String name){
				abs = name.length() != 0 && name.charAt(0) == '/';
				this.name = name;
				StringTokenizer st = new StringTokenizer(name, "/");
				int n = st.countTokens();
				els = new String[n];
				int o = 0;
				for(int i = 0; i < n; i++){	// squeeze out dots
					String s = st.nextToken();
					if(!s.equals("."))
						els[o++] = s;
				}
				if(o == n)
					return;
				String[] shrink = new String[o];
				System.arraycopy(els, 0, shrink, 0, o);
				els = shrink;
				shrink = null;
			}
			Parse(Parse p, int s, int e){	// slice
				abs = p.abs && s == 0;
				name = p.name;
				els = new String[e-s];
				for(int i = 0; i < els.length; i++)
					els[i] = p.els[s+i];
			}
		}

		protected boolean walk(FD ofd, FD fd, Parse p) throws ConnectionFailed, InterruptedIOException {
			Ninep.Rwalk r = (Ninep.Rwalk)conn.ninepreq(ninep.new Twalk(ofd.fid, fd.fid, p.els));
			if(r == null)
				return false;
			if(p.els.length > Ninep.MAXWELEM){
				werrstr("walk too deep");		/* TO DO: chunks of MAXWELEM */
				return false;
			}
			if(r.qids.length != p.els.length){	/* TO DO: chunks of MAXWELEM */
				StringBuilder bs = new StringBuilder(64);
				bs.append('\'');
				if(p.abs)
					bs.append('/');
				int i;
				for(i = 0; i < r.qids.length; i++){
					if(i != 0)
						bs.append('/');
					bs.append(p.els[i]);
				}
				if(i == 0 || (r.qids[i-1].qtype & Qid.QTDIR) != 0){
					if(bs.length() != 0)
						bs.append('/');
					bs.append(p.els[i]);
					bs.append('\'');
					bs.append(' ');
					bs.append(Edoesnotexist);	// could be permission problem
				}else{
					bs.append('\'');
					bs.append(' ');
					bs.append(Enotdir);
				}
				werrstr(bs.toString());
				return false;
			}
			fd.name = ofd.name;
			if(p.els.length > 0){
				for(int i = 0; i < p.els.length; i++)
					fd.name = addname(fd.name, p.els[i]);
				fd.qid = r.qids[r.qids.length-1];
			}else
				fd.qid = ofd.qid;
			return true;
		}
		protected FD walkfrom(Parse p){
			FD ofd = root;
			if(!p.abs){
				FD cwd = getdot();
				if(cwd != null)
					return cwd;	// the reference count in dot will hold it for this process
			}
			return ofd;
		}
		protected boolean walk(FD fd, String name) throws ConnectionFailed, InterruptedIOException {
			Parse p = new Parse(name);
			return walk(walkfrom(p), fd, new Parse(name));
		}
		protected FD walk(String name) throws ConnectionFailed, InterruptedIOException {
			FD fd = conn.newfd();
			try{
				if(!walk(fd, name)){
					fd.free();
					fd = null;
				}
				return fd;
			}catch(ConnectionFailed e){
				fd.free();
				throw e;
			}catch(InterruptedIOException e){
				fd.free();
				throw e;
			}
		}
		protected int opentrunc(FD fd, Parse p, int mode) throws ConnectionFailed, InterruptedIOException {
			/* if able to walk one level, open and truncate */
			if(!walk(fd, fd, new Parse(p, p.els.length-1, p.els.length)))
				return 0;	// doesn't exist
			if((mode & Ninep.OEXCL) != 0){
				werrstr(Eexists);
				return -1;
			}
			/* try an open */
			Ninep.Ropen r = (Ninep.Ropen)conn.ninepreq(ninep.new Topen(fd.fid, mode|Ninep.OTRUNC));
			if(r == null)
				return -1;
			fd.mode = openmode(mode);
			fd.iounit = r.iounit;
			fd.qid = r.qid;
			return 1;
		}
		protected final String addname(String n1, String n2){	// TO DO: move to Strings, or Names class (cf. Names.m)
			if(n1 == null)
				n1 = "";
			if(n2 == null || n2.length() == 0)
				return n1;
			int l1 = n1.length();
			if(n2.equals("..")){
				for(int i = l1; --i >= 1;)
					if(n1.charAt(i) == '/')
						return n1.substring(0, i);
				return "/";
			}
			if(l1 == 0 || n1.charAt(l1-1) != '/')
				return n1+"/"+n2;
			return n1+n2;
		}
	}

	/**
	 * FD represents a file descriptor open on a file in a 9P file system, usually obtained from an operation in FS.
	 * <p>
	 * FD implements a superset of Java nio's interface ByteChannel.
	 * <p>
	 * Extensions include a wider range of read and write operations, both with and without a file offset, and
	 * a set of operations such as <i>stat</i> and <i>dirread</i>, reflecting the underlying 9P operations.
	 */
	public static class FD implements ByteChannel {
		Conn	conn;
		Fid	fidp;
		int		fid;	// arguably should be long, since it's unsigned
		int	mode = -1;
		int	iounit;
		Qid	qid;
		long	offset;
		String	name;	// not yet used

		private FD(Conn conn, Fid fidp){
			this.conn = conn;
			this.fidp = fidp;
			this.fid = fidp.fid;
			this.mode = -1;
			this.iounit = 0;
			this.offset = 0;
			this.name = null;
		}

		// TO DO: readn?

		/**
		 * Return the per-thread error string, which gives the error text from the most recent error.
		 */
		public String errstr() { return NinepClient.errstr(); }

		/**
		 * Set the per-thread error string.
		 */
		public final static void werrstr(String s) { NinepClient.werrstr(s); }

		/**
		 * Return true iff the FD has not been closed.
		 */
		public boolean isOpen(){ return fidp != null; }

		/**
		 * Close the file.
		 * <p>
		 * If not already closed, close the file and <i>clunk</i> the underlying 9P file.
		 * <br>
		 * If already closed, do nothing.
		 */
		public void close(){
			if(fidp != null && fidp.decref() == 0){
				String err = lasterror.get();
				try{
					conn.ninepreq(ninep.new Tclunk(fid));
				}catch(InterruptedIOException e){
					// still considered clunked
				}catch(ConnectionFailed e){
					// let it go: file will be clunked
				}
				lasterror.set(err);
				/* defined to succeed */
				if(conn != null)
					conn.freefid(fidp);
				fidp = null;
			}
		}

		private void open(int mode, int iounit, Qid qid){
			this.mode = mode;
			this.iounit = iounit;
			this.qid = qid;
		}

		private void free(){
			if(fidp != null && fidp.decref() == 0){
				if(conn != null)
					conn.freefid(fidp);
				fidp = null;
			}
			conn = null;
			fid = Ninep.NOFID;
		}

		final void checkio(int mode, int n, long off) throws IOException, ClosedChannelException {
			if(fidp == null)
				throw new ClosedChannelException();
			if(!checkfd(mode))
				ioerror(Ebadusefd);
			if(n < 0)
				ioerror(Etoosmall);
			if(off < 0)
				ioerror(Enegoff);
		}

		/**
		 * Read a sequence of bytes from the file at its current position, into the buffer <i>dest</i>, up to the number of bytes remaining in the buffer.
		 * <p>
		 * Read as many bytes as remain in the buffer, returning the number of bytes read,
		 * which might be zero. (<i>Implements ReadableByteChannel.read</i>, except that concurrent access is allowed.)
		 * <p>
		 * The file's current offset is updated to reflect the bytes read.
		 * <p>
		 * @param	dest	Destination buffer for the bytes read.
		 * @throws		IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public int read(ByteBuffer dest) throws IOException {
			return read(dest, dest.remaining());
		}

		/**
		 * Read up to n bytes into a ByteBuffer from the file starting at the given offset and return number of bytes read (0 at end of file).
		 * @param	dest	Destination buffer for the bytes read.
		 * @param	n	maximum number of bytes to read
		 * @param	offset	byte offset from which to read
		 * @return	number of bytes read, or 0 at end-of-file
		 * @throws		IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public int read(ByteBuffer dest, int n, long offset) throws IOException {
			ByteBuffer rb = read(n, offset);
			if(rb == null)
				return 0;
			n = rb.remaining();
			dest.put(rb);
			return n;
		}

		/**
		 * Read up to n bytes into a ByteBuffer from the file starting at the current offset and return number of bytes read (0 at end of file).
		 * <br>
		 * The file offset is updated to reflect the number of bytes read.
		 * @param	dest	Destination buffer for the bytes read.
		 * @param	n	maximum number of bytes to read
		 * @return	number of bytes read, or 0 at end-of-file
		 * @throws		IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public int	read(ByteBuffer dest, int n) throws IOException {
			long off;
			synchronized(this){ off = offset; }
			n = read(dest, n, off);
			if(n < 0)
				ioerror();
			synchronized(this){ offset += n; }
			return n;
		}

		/**
		 * Return a ByteBuffer containing up to n bytes of data read from the given offset.
		 * <br>
		 * The file's current offset is unchanged.
		 * The buffer is empty at end-of-file.
		 * @param	n	maximum number of bytes to read
		 * @param	offset	byte offset from which to read
		 * @return	ByteBuffer containing the data read, or null at end-of-file.
		 * @throws		IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public ByteBuffer read(int n, long offset) throws  IOException {
			checkio(Ninep.OREAD, n, offset);
			ByteBuffer result = null;
			for(;;){
				int nreq = n;
				if(nreq > conn.msize-IOHDRSZ)
					nreq = conn.msize-IOHDRSZ;
				Ninep.Rread r = (Ninep.Rread)conn.ninepreq(ninep.new Tread(fid, offset, nreq));
				if(r == null)
					ioerror();
				int nr = r.data.remaining();
				if(nr > nreq){	// guard against broken servers
					r.data.limit(r.data.position()+nreq);
					nr = nreq;
				}
				offset += nr;
				n -= nr;
				if(nr != nreq || n == 0){
					// return buffer without copying if only one read was required
					if(result == null || result.position() == 0){
						if(nr == 0)
							return null;
						return r.data;
					}
					result.put(r.data);
					result.flip();
					return result;
				}
				// reading requested n bytes in msize chunks: need a buffer for the whole result
				if(result == null)
					result = ByteBuffer.allocate(n+nr);
				result.put(r.data);
			}
		}

		/**
		 * Read up to n bytes from the file starting at its current offset and return a ByteBuffer containing the bytes read (null at end of file).
		 * @param	n	maximum number of bytes to read
		 * @return	ByteBuffer containing the data read, or null at end-of-file.
		 * @throws		IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public ByteBuffer read(int n) throws IOException {
			long off;
			synchronized(this){ off = offset; }
			ByteBuffer rb = read(n, off);
			if(rb == null)
				return null;
			n = rb.remaining();
			synchronized(this){ offset += n; }
			return rb;
		}

		/**
		 * Read up to n bytes of UTF-8 starting at the current file offset and return the bytes converted to a String, returning null at end-of-file.
		 * @param	n	maximum number of bytes to read
		 * @return	String containing the data read, or null at end-of-file.
		 * @throws		IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public String reads(int n) throws IOException {
			ByteBuffer b = read(n);
			if(b == null)
				return null;
			return Strings.S(b);
		}

		/**
		 * Read up to n bytes of UTF-8 starting at the current file offset and return the bytes converted to a String, returning null at end-of-file.
		 * @param	n	maximum number of bytes to read
		 * @return	String containing the data read, or null at end-of-file.
		 * @throws		IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public String reads(int n, long offset) throws IOException {
			ByteBuffer b = read(n, offset);
			if(b == null)
				return null;
			return Strings.S(b);
		}

		/**
		 * Write a sequence of bytes from the buffer <i>src</i> to the file starting at its current position.
		 * <p>
		 * Write the sequence of bytes remaining in the buffer, returning the number of bytes actually written.
		 * (<i>Implements WritableByteChannel.write</i>, except that concurrent access is allowed.)
		 * <p>
		 * The file's current offset is updated to reflect the bytes written.
		 * @param	src	Source buffer for the bytes to write.
		 * @throws	IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public int write(ByteBuffer src) throws IOException {
			return write(src, src.remaining());
		}

		/**
		 * Write up to <i>n</i> bytes from the buffer <i>src</i> to the file starting at the given offset in bytes.
		 * <p>
		 * Write the sequence of bytes remaining in the buffer, but no more than <i>n</i>, returning the number of bytes actually written.
		 * <br>
		 * The file offset is unchanged.
		 * @param	src	Source buffer for the bytes to write.
		 * @param	n	maximum number of bytes to write.
		 * @param	offset	starting byte offset in file
		 * @return	number of bytes written
		 * @throws	IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public int write(ByteBuffer src, int n, long offset) throws IOException {
			checkio(Ninep.OWRITE, n, offset);
			if((qid.qtype & Qid.QTDIR) != 0)
				ioerror(Eisdir);	// probably can't happen: can't open directory OWRITE
			int count = 0;
			for(;;){
				int nreq = n;
				if(nreq > conn.msize-IOHDRSZ)
					nreq = conn.msize-IOHDRSZ;
				Ninep.Rwrite r = (Ninep.Rwrite)conn.ninepreq(ninep.new Twrite(fid, offset, src, nreq));
				if(r == null)
					ioerror();
				int nr = r.count;
				if(nr > nreq)
					nr = nreq;
				offset += nr;
				n -= nr;
				count += nr;
				src.position(src.position()+nr);
				if(nr != nreq || n == 0)
					break;
			}
			return count;
		}

		/**
		 * Write up to <i>n</i> bytes from the buffer <i>src</i> to the file starting at the current file offset.
		 * <p>
		 * Write the sequence of bytes remaining in the buffer, but no more than <i>n</i>, returning the number of bytes actually written.
		 * <br>
		 * The file offset is updated to reflect the number of bytes actually written.
		 * @param	src	Source buffer for the bytes to write.
		 * @param	n	maximum number of bytes to write.
		 * @return	number of bytes written
		 * @throws	IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public int	write(ByteBuffer src, int n) throws IOException {
			long off;
			checkio(Ninep.OWRITE, n, 0);
			synchronized(this){ off = offset; offset += n; }	// assume it all goes
			int r = 0;
			try{
				r = write(src, n, off);
			}catch(IOException e){
				synchronized(this){ offset -= n; }
				throw e;
			}
			if(r < n)
				synchronized(this){ offset -= n-r; }
			return r;
		}

		/**
		 * Write all the bytes from the byte array <i>buf</i> to the file starting at the current file offset.
		 * <br>
		 * The file offset is updated to reflect the number of bytes actually written.
		 * @param	buf	Source buffer for the bytes to write.
		 * @return	number of bytes written
		 * @throws	IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public int write(byte[] buf) throws IOException {
			return write(ByteBuffer.wrap(buf));
		}

		/**
		 * Write all the bytes from the byte array <i>buf</i> to the file starting at the given file offset.
		 * <br>
		 * The file offset is unchanged.
		 * @param	buf	Source buffer for the bytes to write.
		 * @param	offset	byte offset at which to start writing
		 * @return	number of bytes written
		 * @throws	IOException	In case of any IO error: the exception's message gives the cause.
		 */
		public int write(byte[] buf, long offset) throws IOException {
			return write(ByteBuffer.wrap(buf), buf.length, offset);
		}

		/**
		 * Write the bytes of the UTF-8 encoding of String <i>s</i> to the file.
		 * <p>
		 * Returns the number of bytes written. Throws an exception if not all bytes were written.
		 *
		 * @param	s	The string to write to the file
		 * @return	The number of bytes written.
		 * @throws	IOException	Not all the bytes were successfully written; and any other error.
		 */
		public int write(String s) throws IOException {
			byte a[] = Strings.bytes(s);
			if(write(a, a.length) != a.length)
				ioerror("write truncated");
			return a.length;
		}

		/**
		 * Read an array of <i>Dir</i> values from a directory.
		 * <p>
		 * The file must be a directory, or an exception results.
		 * Return an array containing a sequence of directory entries read from the directory at its current offset,
		 * or null if at the end of the directory.
		 *
		 * @return	An array of <i>Dir</i> values, or null if no more directory entries remain.
		 * @throws	IOException	On any error when trying to read the directory.
		 */
		public Dir[] dirread() throws IOException {
			ByteBuffer b;
			b = read(4096);		// arbitrary value bigger than largest single directory entry
			if(b == null)
				return null;
			ArrayList<Dir> v = new ArrayList<Dir>(b.remaining()/Ninep.STATFIXLEN);
			dirunpack(b, v);
			return dirents(v, false);
		}

		/**
		 * Read an array of all <i>Dir</i> values remaining in a directory.
		 * <p>
		 * The file must be a directory, or an exception results.
		 * Return an array containing a sequence of all remaining directory entries read from the directory at its current offset,
		 * or null if at the end of the directory.
		 *
		 * @return	An array of <i>Dir</i> values, which will be empty (length 0) if no more directory entries remain.
		 * @throws	IOException	On any error when trying to read the directory.
		 */
		public Dir[] dirreadall() throws IOException {
			ByteBuffer b;
			ArrayList<Dir> v = new ArrayList<Dir>(256);	// arbitrary
			while((b = read(4096)) != null)
				if(!dirunpack(b, v))
					break;
			return dirents(v, true);
		}

		/**
		 * Return the directory entry (<I>Dir</i> value) that describes the current file
		 * <p>
		 * @return	A <i>Dir</i> instance that describes the current file.
		 * @throws	IOException	On any error.
		 */
		public Dir stat() throws IOException {
			Dir d = qstat();
			if(d == null)
				ioerror();
			return d;
		}

		// quiet version, for internal use: doesn't raise exception
		private Dir qstat() {
			try{
				Ninep.Rstat r = (Ninep.Rstat)conn.ninepreq(ninep.new Tstat(fid));
				if(r == null)
					return null;
				return r.stat;
			}catch(InterruptedIOException e){
				return null;
			}catch(ConnectionFailed e){
				return null;
			}
		}

		/**
		 * Attempt to update the directory entry for the current file, returning true on success.
		 * <p>
		 * The <i>Dir</i> parameter has a special form: values that should not change will either be the
		 * file's original values, or special "don't care" values, described in <i>stat</i>(5), typically null or
		 * empty strings for string values, and ~0 for integer values. Any other values will change the file's
		 * directory entry to match. If the request is rejected, <i>wstat</i> returns false and updates the error string.
		 * @param	d	A <i>Dir</i> instance containing the values to update
		 * @return	true iff the file server accepted the update
		 *	@throws	InterruptedIOException	operation was interrupted (eg, by an alarm)
		 *	@throws	ConnectionFailed	9P connection was shut down, by hangup or IO error
		 */
		public boolean wstat(Dir d) throws ConnectionFailed, InterruptedIOException {
			Ninep.Rwstat r = (Ninep.Rwstat)conn.ninepreq(ninep.new Twstat(fid, d));
			return r != null;
		}

		/**
		 * Change the current file position (offset)
		 * <p>
		 * Interpret <i>off</i> as instructed by <i>whence</i> and change the file's current position to that value.
		 * @param	off	Either an absolute ({@link NinepClient#SEEKSTART}) or relative ({@link NinepClient#SEEKRELA}, {@link NinepClient#SEEKEND}) file offset in bytes.
		 * @param	whence	{@link NinepClient#SEEKSTART} (absolute offset), {@link NinepClient#SEEKRELA} (signed offset from the current position), or {@link NinepClient#SEEKEND} (signed offset from the length of the file)
		 * @return	The resulting offset, or -1 if the attempt failed.
		 */
		public long seek(long off, int whence){
			switch(whence){
			case SEEKSTART:
				if((qid.qtype & Qid.QTDIR) != 0 && off != 0){
					werrstr(Eisdir);
					return -1;
				}
				synchronized(this){ offset = off; }
				break;
			case SEEKRELA:
				if((qid.qtype & Qid.QTDIR) != 0){
					werrstr(Eisdir);
					return -1;
				}
				synchronized(this){
					off += offset;
					if(off < 0){
						werrstr(Enegoff);
						return -1;
					}
					offset = off;
				}
				break;
			case SEEKEND:
				if((qid.qtype & Qid.QTDIR) != 0){
					werrstr(Eisdir);
					return -1;
				}
				Dir d = qstat();
				if(d == null){
					werrstr("internal error: stat error in seek: "+errstr());
					return -1;
				}
				off += d.length;
				if(off < 0){
					werrstr(Enegoff);
					return -1;
				}
				synchronized(this){ offset = off; }
				break;
			default:
				werrstr("invalid argument");
				return -1;
			}
			return off;	// not offset, that might already have changed
		}

		/** Return the path name by which this file was opened */
		public String path(){
			return this.name;
		}

		/** Return the suggested buffer size in bytes for reads and writes, or 0 if unspecified */
		public int iounit(){
			return this.iounit;
		}

		// extensions for Java

		/**
		 * Return the current file position (offset in bytes)
		 * @return	A 64-bit integer giving the current file offset in bytes.
		 */
		public long position(){
			synchronized(this){
				return this.offset;
			}
		}

		/**
		 * Set the current file position to the given offset in bytes.
		 * <p>
		 * @param	offset	The desired offset
		 * @throws	IOException	If the offset is negative or the offset is non-zero for a directory, and on any other error.
		 */
		public void setPosition(long offset) throws IOException {
			if(offset < 0)
				ioerror(Enegoff);
			if(offset != 0 && (this.qid.qtype & Qid.QTDIR) != 0)
				ioerror(Eisdir);
			synchronized(this){
				this.offset = offset;
			}
		}

		/**
		 * Return true if the file is a directory.
		 */
		public boolean isDirectory(){
			return (this.qid.qtype & Qid.QTDIR) != 0;
		}

		/**
		 * Return true if the file is marked "exclusive-use" (DMEXCL)
		 */
		public boolean isExclusive(){
			return (this.qid.qtype & Qid.QTEXCL) != 0;
		}

		/**
		 * Return true if the file is marked "append-only" (DMAPPEND)
		 */
		public boolean isAppendOnly(){
			return (this.qid.qtype & Qid.QTAPPEND) != 0;
		}

		protected boolean checkfd(int m){
			if(mode < 0)
				return false;	// not opened
			if(mode != Ninep.ORDWR){
				if((m & Ninep.OTRUNC) != 0 && mode == Ninep.OREAD ||
				   (m & ~Ninep.OTRUNC) != mode){
					return false;
				}
			}
			return true;
		}

	}

	static final protected int openmode(int m){
		m &= 3;
		if(m == Ninep.OEXEC)
			return Ninep.OREAD;
		return m;
	}

	protected static final boolean dirunpack(ByteBuffer buf, ArrayList<Dir> v){
		boolean found = false;
		while(buf.remaining() > 0){
			try{
				v.add(Ninep.unpackdir(buf));
				found = true;
			}catch(Ninep.FormatError e){
				// server error?
				break;
			}
		}
		return found;
	}
	protected static final Dir[] dirents(ArrayList<Dir> v, boolean empty){
		if(!empty && v.size() == 0)
			return null;
		return v.toArray(new Dir[v.size()]);
	}

	/* tags are shared by all clients and all connections */
	static private final int Tagshift = 5;
	static private final int Tagmask = (1<<Tagshift)-1;
	static private final int Tagwords = (64*1024)>>Tagshift;
	static int[]	tagbits = new int[Tagwords];	// might need to be done in constructor

	static protected int gettag(){
		synchronized(tagbits){
			for(int i = 0;  i < Tagwords; i++){
				int v = tagbits[i];
				if(v != ~0){
					for(int j = 0; j <= Tagmask; j++)
						if((v & (1<<j)) == 0){
							tagbits[i] |= (1<<j);
							return i*(1<<Tagshift) + j;
						}
				}
			}
		}
		return Ninep.NOTAG;
	}
	static protected void puttag(int tag){
		if(tag != Ninep.NOTAG)
			synchronized(tagbits){
				tagbits[tag >> Tagshift] &= ~(1 << (tag & Tagmask));
			}
	}
	static private void settag(int tag){
		//assert tag != Ninep.NOTAG;
		synchronized(tagbits){
			tagbits[tag >> Tagshift] |= 1 << (tag & Tagmask);
		}
	}

	static private void nullity(){}
}
