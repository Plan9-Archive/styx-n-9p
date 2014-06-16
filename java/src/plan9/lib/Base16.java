package plan9.lib;

import java.lang.StringBuilder;

// from styx-n-9p.googlecode.com (MIT licence)
public class Base16 implements Encoding {

	private final static char[] hex = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

	public final String enc(byte[] a){
		StringBuilder o = new StringBuilder();
		for(byte b : a) {
			int n = (int)b & 0xFF;
			o.append(hex[n>>4]);
			o.append(hex[n & 0xF]);
		}
		return o.toString();
	}

	// this is compatible with both dec16 and strtomp on Plan 9, in handling of odd length
	public final byte[] dec(String s){
		int l = s.length();
		byte[] a = new byte[(l+1)/2];
		int o = 0;
		int j = l & 1;	// add extra 0 nibble at front if odd length, equivalent to right-justifying value
		int n = 0;
		for(int i = 0; i < l; i++){
			char c = s.charAt(i);
			n <<= 4;
			if(c >= '0' && c <= '9')
				n |= c - '0';
			else if(c >= 'A' && c <= 'F')
				n |= c-'A'+10;
			else if(c >= 'a' && c <= 'f')
				n |= c-'a'+10;
			else
				continue;
			if(++j == 2){
				a[o++] = (byte)n;
				j = n = 0;
			}
		}
		return a;
	}
}
