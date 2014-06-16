package plan9.auth;

public class LocalAuthErr extends AuthenticationException {
	public LocalAuthErr(String s){ super(s); }
	public LocalAuthErr(String s, Throwable cause){ super(s, cause); }
}
