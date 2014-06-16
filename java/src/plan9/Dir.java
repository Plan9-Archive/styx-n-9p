package plan9;

// Dir, from styx-n-9p.googlecode.com (MIT Licence)

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
 * <p>
 * The bits in mode are defined by
 * <p>
 *     0x80000000   directory	<br>
 *     0x40000000   append only	<br>
 *     0x20000000   exclusive use (locked when open) <br>
 * <p>
 * 	 0400   read permission by owner	<br>
 * 	 0200   write permission by owner	<br>
 * 	 0100   execute permission (search on directory) by owner	<br>
 * 	 0070   read, write, execute (search) by group	<br>
 * 	 0007   read, write, execute (search) by others	<br>
 * <p>
 * There are constants defined in for these bits:
 * DMDIR, DMAPPEND, and DMEXCL for the first three; and DMREAD,
 * DMWRITE, and DMEXEC for the read, write, and execute bits for others.
 * <p>
 * The two time fields are measured in seconds since the epoch
 * (Jan 1 00:00 1970 GMT).  Mtime is the time of the last
 * change of content.  Similarly, atime is set whenever the
 * contents are accessed; also, it is set whenever mtime is set.
 * <p>
 * If the file resides on permanent storage and is
 * not a directory, the length returned by stat is the number
 * of bytes in the file.  For directories, the length returned
 * is zero.
 * <p>
 * Uid and gid are the names of the owner and group of the
 * file; muid is the name of the user that last modified the
 * file (setting mtime).
 * <p>
 * Groups are also users, but each server is free to associate a list of users with any user
 * name g, and that list is the set of users in the group g.
 * <p>
 * The server knows, for any given file access, whether
 * the accessing process is the owner of, or in the group of,
 * the file.  This selects which sets of three bits in mode is
 * used to check permissions.
 */
public class Dir {
	/** last element of file's path name */
	public String	name;

	/** user name */
	public String	uid;		

	/** group name */
	public String	gid;		

	/** last modifier name */
	public String	muid;	

	/** unique ID from seerver */
	public Qid		qid;		

	/** permissions (see below) */
	public int		mode;	

	/** last access time in seconds from Epoch */
	public int		atime;	

	/** last modification time in seconds from Epoch */
	public int		mtime;	

	/** length in bytes (0 for directory) */
	public long	length;	

	// ``system-modified data'' (leave them 0 or ~0)

	/** server type */
	public int		dtype;	

	/** server subtype */
	public int		dev;		

	// mode bits in Dir.mode used by the protocol

	/** directory */
	public static final int	DMDIR = 1<<31;	

	/** append-only file */
	public static final int	DMAPPEND = 1<<30;

	/** exclusive use file */
	public static final int	DMEXCL = 1<<29;	

//	/* mounted channel (internal use) */
//	public static final int DMMOUNT = 1<<28;

	/** authentication file */
	public static final int	DMAUTH = 1<<27;	

	/** not-backed-up */
	public static final int	DMTMP  = 1<<26;	

	// permission bits (for others; use <<3 for group, <<6 for owner)

	/** read */
	public static final int DMREAD = 1<<2;

	/** write */
	public static final int DMWRITE = 1<<1;

	/** execute */
	public static final int DMEXEC = 1<<0;

	private static final String[] rwx = {
		"---",	"--x",	"-w-",
		"-wx",	"r--",	"r-x",
		"rw-",	"rwx",
	};

	/** Create a Dir value that is completely zero */
	public Dir(){ }

	/** Create a Dir value that has the given values for name, qid, length, and mode */
	public Dir(String name, Qid qid, long length, int mode){
		this.name = name; this.qid = qid; this.length = length; this.mode = mode;
	}

	/** Return a string that gives a printable version of all components of a Dir value */
	public String toString(){
		return String.format("Dir(\"%s\",\"%s\",\"%s\",\"%s\",%s,%01o,%d,%d,%d,0x%x,%d)",
			name, uid, gid, muid, qid, mode, atime, mtime, length, dtype, dev);
	}

	/** Return a string that represents the mode bits in the same style as ls(1) */
	public String modefmt(){
		return modefmt(mode);
	}

	/** Return a string that represents the mode bits <i>m</i> in the same style as ls(1) */
	public static String modefmt(int m){
		String p0, p1;
		if((m & DMDIR) != 0)
			p0 = "d";
		else if((m & DMAPPEND) != 0)
			p0 = "a";
		else if((m & DMAUTH) != 0)
			p0 = "A";
		else
			p0 = "-";
		if((m & DMEXCL) != 0)
			p1 = "l";
		else
			p1 = "-";
		return p0 + p1 + rwx[(m>>6)&7] + rwx[(m>>3)&7] + rwx[m&7];
	}

	/** Return a special Dir value with all fields marked as `no change', for use as a modifiable prototype for <i>wstat</i> calls */
	public static final Dir nulldir() {
		Dir d = new Dir();
		d.qid = new Qid(~0L, ~0, ~0);
		d.mode = ~0;
		d.atime = d.mtime = ~0;
		d.length = ~0L;
		d.dtype = d.dev = ~0;
		// names remain null
		return d;
	}

	// extensions to make it more Java-like

	/** Return true iff the corresponding file is a directory */
	public boolean isDirectory() {
		return (this.mode & DMDIR) != 0;
	}

	/** Return true iff the file is append-only */
	public boolean isAppendOnly() {
		return (this.mode & DMAPPEND) != 0;
	}

	/** Return true iff the file is exclusive-use */
	public boolean isExclusive() {
		return (this.mode & DMEXCL) != 0;
	}

	/** Return true iff the file is owner-readable (in Plan 9, any of owner, group or world permission allowing reading) */
	public boolean isOwnerReadable(){
		return (this.mode & 0444) != 0;
	}

	/** Return true iff the file is group-readable (in Plan 9, either group or world permissions allow reading) */
	public boolean isGroupReadable(){
		return (this.mode & 044) != 0;
	}

	/** Return true iff the file is world-readable */
	public boolean isWorldReadable(){
		return (this.mode & 4) != 0;
	}

	/** Return true iff the file is owner-readable (in Plan 9, any of owner, group or world permission allowing writing) */
	public boolean isOwnerWritable(){
		return (this.mode & 0222) != 0;
	}

	/** Return true iff the file is group-readable (in Plan 9, either group or world permissions allow writing) */
	public boolean isGroupWritable(){
		return (this.mode & 022) != 0;
	}

	/** Return true iff the file is world-readable */
	public boolean isWorldWritable(){
		return (this.mode & 2) != 0;
	}

	/** Return true iff the file is a directory and owner-searchable (in Plan 9, any of owner, group or world permission allowing searching) */
	public boolean isOwnerSearchable(){
		return (this.mode&DMDIR) != 0 && (this.mode & 0111) != 0;
	}

	/** Return true iff the file is a directory and is group-searchable (in Plan 9, either group or world permissions allow searching) */
	public boolean isGroupSearchable(){
		return (this.mode&DMDIR) != 0 && (this.mode & 011) != 0;
	}

	/** Return true iff the file is a directory and is world-searchable */
	public boolean isWorldSearchable(){
		return (this.mode&DMDIR) != 0 && (this.mode & 1) != 0;
	}
}
