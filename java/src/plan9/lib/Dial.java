package plan9.lib;

import java.lang.Integer;
import java.util.Map;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.nio.channels.SocketChannel;
import java.net.*;

// Plan 9/Inferno Dial interface to make network connections
// from styx-n-9p.googlecode.com (MIT licence)

/**
 * Dial makes network connections, using a network-independent textual form of addressing services on hosts.
 * It is based on Plan 9's <i>dial</i>(2). The current implementation supports only TCP/IP,
 * but the same interface can support non-Internet protocols without change.
 * It encapsulates the translation of textual forms of host and service names into IP addresses and port numbers,
 * allowing network connections to be made with a single call. Unlike <code>new Socket(hostname, port)</code>,
 * which is also a single operation, Dial guarantees that it will try all addresses for a host, has an interface not limited to IP networking, and will translate
 * Plan 9 service names to port numbers.
 * <p>
 * It knows the correct port numbers for various Plan 9 services, such as <b>9fs</b>, <b>exportfs</b> and <b>ticket</b>.
 * <p>
 * Instead of raising exceptions, Dial returns an error value and makes the diagnostic available in a per-thread error string.
 * <p>
 * There is no constructor: Dial contains only static values and methods.
 * <p>
 *
 * For example, combining dial and netmkaddr to connect to a <b>9fs</b> service:
 * <pre>
 *	ByteChannel fd = Dial.dial(Dial.netmkaddr(args[0], "net", "9fs"), null);
 *	if(fd == null)
 *		error(String.format("can't dial %s: %s", args[0], Dial.errstr());
 * </pre>
 */
public class Dial {

	private Dial(){}

	private static ThreadLocal<String> lasterror = new ThreadLocal<String>();

	/** Return the per-thread error string: the diagnostic from the last failed operation */
	public final static String errstr() { return lasterror.get(); }

	/** Set the per-thread error string to the string <i>s</i> */
	public final static void werrstr(String s) { lasterror.set(s); }

	private static Map<String,Integer> portmap = new HashMap<String,Integer>(){{
		put("tcp!9fs", 564);
		put("tcp!whoami", 565);
		put("tcp!guard", 566);
		put("tcp!ticket", 567);
		put("tcp!exportfs", 17007);
		put("tcp!rexexec", 17009);
		put("tcp!ncpu", 17010);
		put("tcp!cpu", 17013);
		put("tcp!venti", 17034);
		put("tcp!wiki", 17035);
		put("tcp!secstore", 5356);
		put("udp!dns", 53);
		put("tcp!dns", 53);
		put("tcp!styx", 6666);
		put("tcp!infsched", 6678);	// owen
	}};

	/**
	 * Dial (make a network connection to) the given destination network address.
	 * The address (or "dial string") has the form <i>net</i><b>!</b><i>host</i><b>!</b><i>service</i>,
	 * where
	 * <dl>
	 * <dt><i>net</i><dd>is a network or protocol. Use <b>net</b> to represent any network on which the host is found.
	 * Use <b>tcp</b> to force the use of TCP/IP.
	 * <dt><i>host</i><dd>is a symbolic name (eg, host name or DNS name), or a network address in textual form (eg, an IP address such as 127.0.0.1).
	 * <dt><i>service</i><dd>is a symbolic name for the desired service, for instance <b>telnet</b>, or a numeric port number.
	 * It can be any name supported by UNIX's <i>getservbyname</i>.
	 * </dl>
	 * {@link Dial#netmkaddr} builds a dial string from its three components, adding defaults as required.
	 * <p>
	 * Dial tries each possible network address for a host (a host name might correspond to several network addresses),
	 * until one succeeds, or all have failed. On success, dial returns a SocketChannel value giving a full-duplex
	 * connection to the remote host. On an error, it returns null, setting the error string to the diagnostic.
	 *
	 * @param	dest	network address in the form <i>net</i><b>!</b><i>host</i><b>!</b><i>service</i>.
	 * @param	local	leave null or "" to use any local port (other values reserved for future use)
	 * @return		a SocketChannel value representing a full-duplex connection to the remote host, or null on any error
	 */
	static public final SocketChannel dial(String dest, String local){
		StringTokenizer flds = new StringTokenizer(dest, "!");
		int n = flds.countTokens();
		if(n < 3){
			werrstr("invalid network address for dial: "+dest);
			return null;
		}
		String net = flds.nextToken();
		String host = flds.nextToken();
		String svc = flds.nextToken();
		if(net.equals("net"))
			net = "tcp";
		else if(!net.equals("tcp")){	// TO DO: "udp"
			werrstr("no network to host: "+dest);
			return null;
		}
		InetAddress[] addrs;
		try{
			addrs = InetAddress.getAllByName(host);
		}catch(UnknownHostException e){
			werrstr("unknown host: "+host);
			return null;
		}
		int port = portno(svc);
		if(port < 0){
			Integer p = portmap.get(net+"!"+svc);
			if(p == null){
				werrstr("can't translate service: "+svc);
				return null;
			}
			port = p.intValue();
		}
		for(InetAddress ip : addrs){
			try{
				SocketChannel sc = SocketChannel.open(new InetSocketAddress(ip, port));
				if(sc != null){
					sc.socket().setTcpNoDelay(true);
					return sc;
				}
			}catch(java.io.IOException e){
				werrstr(e.getMessage());
			}
		}
		return null;
	}

	/**
	 * Add default network and service components as required to an address in {@link Dial#dial}'s form.
	 * The address has {@link Dial#dial}'s <i>net</i><b>!</b><i>host</i><b>!</b><i>service</i> form,
	 * but if <i>net</i> and <i>svc</i> are missing (ie, the address is just a host name), netmkaddr
	 * will add them, using the values of its {@code net} and {@code svc} parameters. If only the <i>service</i>
	 * is missing, netmkaddr will add it, using {@code svc}.
	 * @param	addr	an address in one of the forms net!host!svc, net!host, or simply host
	 * @param	net	default network name to use if addr hasn't got one
	 * @param	svc	default service name to use if addr hasn't got one
	 * @return a complete dial string
	 */
	static public final String netmkaddr(String addr, String net, String svc){
		StringTokenizer flds = new StringTokenizer(addr, "!");
		int n = flds.countTokens();
		if(n <= 1){
			if(net == null)
				net = "net";
			if(svc == null)
				return net+"!"+addr;
			return net+"!"+addr+"!"+svc;
		}
		if(svc != null && n < 2)
			return addr+"!"+svc;
		return addr;
	}

	static private int portno(String s){
		int n = 0;
		for(int i = 0; i < s.length(); i++){
			char c = s.charAt(i);
			if(!(c >= '0' && c <= '9'))
				return -1;
			n = n*10 + ((int)c-'0');
		}
		return n;
	}
}
