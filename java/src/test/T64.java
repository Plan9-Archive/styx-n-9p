import plan9.lib.Base64;

// test base64 decoding
public class T64 {
	public static void main(String[] args){
		Base64 base64 = new Base64();
		String s = base64.enc(args[0].getBytes());
		System.out.println(s.length()+": "+s);
	}
}
