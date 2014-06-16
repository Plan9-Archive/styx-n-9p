package plan9.ssl;

public interface Encryption {
	void	encrypt(byte[] buf, int offset, int length);
	void	decrypt(byte[] buf, int offset, int length);
};
