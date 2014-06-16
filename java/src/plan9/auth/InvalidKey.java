package plan9.auth;

public class InvalidKey extends AuthenticationException {
	public InvalidKey(String s){ super(s); }
	public InvalidKey(String s, Throwable cause){ super(s, cause); }
}
