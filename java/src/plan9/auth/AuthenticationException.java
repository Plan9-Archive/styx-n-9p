package plan9.auth;

public class AuthenticationException extends Exception {
	public AuthenticationException(String s){ super(s); }
	public AuthenticationException(String s, Throwable cause){ super(s, cause); }
}
