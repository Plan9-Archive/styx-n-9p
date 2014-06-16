package plan9.auth;

public class RemoteAuthErr extends AuthenticationException {
	public RemoteAuthErr(String s){ super(s); }
	public RemoteAuthErr(String s, Throwable cause){ super(s, cause); }
}
