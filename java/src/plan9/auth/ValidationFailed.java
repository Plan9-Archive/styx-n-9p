package plan9.auth;

public class ValidationFailed extends AuthenticationException {
	public ValidationFailed(String s){ super(s); }
	public ValidationFailed(String s, Throwable cause){ super(s, cause); }
}
