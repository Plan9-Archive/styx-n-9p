package plan9;

// Qid, from styx-n-9p.googlecode.com (MIT Licence)

/**
 * Each file is the responsibility of some server: it could be
 * a file server, a kernel device, or a user process.  Type
 * identifies the server type, and dev says which of a group of
 * servers of the same type is the one responsible for this
 * file.  Qid is a structure containing path and vers fields:
 * path is guaranteed to be unique among all path names currently on the file server,
 * and vers changes each time the file is modified.
 * The path is a 64-bit integer and the vers is an unsigned
 * 32-bit integer (represented in Java by a long).
 * Thus, if two files have the same type, dev, and qid they are the same file.
 */
public class Qid {

	/** 64-bit value, unique to a file on a given file server */
	public long	path;	

	/** 32-bit unsigned value incremented on each write */
	public int		vers;	

	/** file's type: the top 8 bits of its Dir.mode */
	public int		qtype;

	// Qid.qtype type bits

	/** directory */
	public static final int	QTDIR = 0x80;	

	/** append-only file */
	public static final int	QTAPPEND = 0x40;

	/** exclusive-use file */
	public static final int	QTEXCL = 0x20;

	/** authentication file */
	public static final int	QTAUTH = 0x08;

	/** not-backed-up file (symbolic link in 9P200.u) */
	public static final int	QTTMP = 0x04;	

	/** plain file */
	public static final int	QTFILE = 0x00;	

	/** Create a new Qid value with given path and type, and version zero */
	public Qid(long path, int qtype){
		this.path = path; this.vers = 0; this.qtype = qtype;
	}

	/** Create a new Qid value with given path, vers(ion), and type */
	public Qid(long path, int vers, int qtype){
		this.path =  path; this.vers = vers; this.qtype = qtype;
	}

	/** Return true iff Object <i>o</i> is a Qid of equal value */
	public boolean equals(Object o){
		if(o == null || !(o instanceof Qid))
			return false;
		if(o == this)
			return true;
		Qid q = (Qid)o;
		return path == q.path && vers == q.vers && qtype == q.qtype;
	}

	/** Return a value usable as a Java hash code */
	public int hashCode(){
		return (int)path ^ vers ^ qtype;
	}

	/** Return a string with a printable version of the Qid components */
	public String toString(){
		return String.format("(%016x %d %02x)", path, vers, qtype);
	}

	/** Return a string with a printable version of the Qid [q]type */
	public String qidtype(){
		char[] s = new char[5];
		int i = 0;
		if((qtype & QTDIR) != 0)
			s[i++] = 'd';
		if((qtype & QTAPPEND) != 0)
			s[i++] = 'a';
		if((qtype & QTEXCL) != 0)
			s[i++] = 'l';
		if((qtype & QTAUTH) != 0)
			s[i++] = 'A';
		if((qtype & QTTMP) != 0)
			s[i++] = 'T';
		return new String(s, 0, i);
	}
}
