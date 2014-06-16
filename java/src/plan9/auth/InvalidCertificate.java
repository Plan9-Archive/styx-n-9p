package plan9.auth;

public class InvalidCertificate extends AuthenticationException {
	public InvalidCertificate(String s){ super(s); }
	public InvalidCertificate(String s, Throwable cause){ super(s, cause); }
}
