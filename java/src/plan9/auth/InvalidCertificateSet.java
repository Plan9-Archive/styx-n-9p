package plan9.auth;

public class InvalidCertificateSet extends AuthenticationException {
	public InvalidCertificateSet(String s){ super(s); }
	public InvalidCertificateSet(String s, Throwable cause){ super(s, cause); }
}
