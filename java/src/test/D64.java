import plan9.lib.Base64;

// test base64 decoding
public class D64 {
	public static void main(String[] args){
		Base64 base64 = new Base64();
		byte[] b = base64.dec(args[0]);
		System.out.println(b.length+": "+new String(b));
	}
}
