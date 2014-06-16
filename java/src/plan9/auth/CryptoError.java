package plan9.auth;

public class CryptoError extends AuthenticationException {
	public CryptoError(String s){ super(s); }
	public CryptoError(String s, Throwable cause){ super(s, cause); }
}
