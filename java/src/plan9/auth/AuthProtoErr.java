package plan9.auth;

public class AuthProtoErr extends AuthenticationException {
	public AuthProtoErr(String s){ super(s); }
	public AuthProtoErr(String s, Throwable cause){ super(s, cause); }
}
