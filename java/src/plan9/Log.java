package plan9;

public interface Log {

	static final int Off = 0;
	static final int Fatal = 1;
	static final int Error = 2;
	static final int Warn = 3;
	static final int Info = 4;
	static final int Debug = 5;
	static final int Trace = 6;
	static final int All = 7;

	public	Log	newlog(Class tag);
	public	void	setlevel(int level);
	public	boolean	logging();
	public	boolean	debugging();
	public	boolean	tracing();
	public	void	info(String fmt, Object... things);
	public	void	trace(String fmt, Object... things);
	public	void	debug(String fmt, Object... things);
	public	void	warn(String fmt, Object... things);
	public	void	error(String fmt, Object... things);
	public	void	fatal(String fmt, Object... things);	// not sure there are any
}
