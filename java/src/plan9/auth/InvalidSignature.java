package plan9.auth;

public class InvalidSignature extends AuthenticationException {
	public InvalidSignature(String s){ super(s); }
	public InvalidSignature(String s, Throwable cause){ super(s, cause); }
}
