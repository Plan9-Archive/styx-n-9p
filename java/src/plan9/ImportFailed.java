package plan9;

/** An import operation failed for the given reason */
public class ImportFailed extends Exception {
	public ImportFailed(String s){
		super(s);
	}
	public ImportFailed(String s, Throwable cause){
		super(s, cause);
	}
}
