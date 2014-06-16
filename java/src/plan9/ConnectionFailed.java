package plan9;

import java.io.IOException;

/** A 9P connection failed for the given reason */
public class ConnectionFailed extends IOException {
	public ConnectionFailed(String s){
		super(s);
	}
	public ConnectionFailed(String s, Throwable cause){
		super(s, cause);
	}
}
