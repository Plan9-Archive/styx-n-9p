package plan9.lib;

// TO DO: exceptions on bad encodings
// from styx-n-9p.googlecode.com, MIT Licence
public interface Encoding {
	public String enc(byte[] a);
	public byte[] dec(String s);
}
