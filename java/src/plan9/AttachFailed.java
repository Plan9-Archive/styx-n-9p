package plan9;

/** A 9P attach operation failed for the given reason */
public class AttachFailed extends Exception {
	public AttachFailed(String s){
		super(s);
	}
	public AttachFailed(String s, Throwable cause){
		super(s, cause);
	}
}
