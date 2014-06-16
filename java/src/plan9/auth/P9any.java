package plan9.auth;

import java.util.ArrayList;

import plan9.lib.*;

import plan9.LogFactory;
import plan9.Log;

/*
 * p9any implementation
 * 
 * a Java variant of Inferno's implementation in Limbo (LGPL, now MIT Licence)
 *
 * generalised from com.vitanuova.auth.P9any
 * Java version revisions Copyright © 2012 Coraid Inc
 */

public class P9any implements Authproto {

	static final Log log = LogFactory.logger(P9any.class);	// could probably build this into AuthIO

	public P9any(){}

	public String name(){
		return "p9any";
	}

	public String init(AuthIO io){
		return null;
	}

	public String interaction(AuthIO io, Attrs attrs) throws AuthenticationException, CryptoError {
		String role = attrs.findattrval("role");
		if(role == null)
			return "role not specified";
		if(!role.equals("client"))
			return "only client role supported";	// TO DO
		return p9any(io, attrs);
	}

	private static class Dom {
		String	dom;
		String	proto;
		ArrayList<Key>	keys;

		Dom(String dom, String proto, ArrayList<Key> keys){
			this.dom = dom;
			this.proto = proto;
			this.keys = keys;
		}
	}

	String p9any(AuthIO io, Attrs attrs) throws AuthenticationException, CryptoError {
		byte[] buf;
		int n;
		String[] fields;
		String err;
		boolean sharedproto;

		io.newphase("p9any wait for server announcement");
		while((buf = io.read()) == null || (n = buf.length) == 0 || buf[n-1] != (byte)0)
			io.toosmall(2048);
		io.newphase(null);
		String s = Strings.S(buf, 0, n-1);
		if(log.debugging())
			log.debug("s=%s", s);
		fields = Strings.unquoted(s);
		int version = 1;
		if(fields.length > 0 && fields[0].length() >= 2 && fields[0].substring(0,2).equals("v.")){
			if(fields[0].equals("v.2")){
				version = 2;
				if(log.debugging())
					log.debug("version 2");
			}else
				return "p9any: unknown version";
		}
		// TO DO: various protocols
		sharedproto = false;
		ArrayList<Dom> doms = new ArrayList<Dom>();
		int f = version == 2? 1: 0;
		for(; f < fields.length; f++){
			int at = fields[f].indexOf('@');
			String p = at < 0? fields[f]: fields[f].substring(0, at);
			String dom = at < 0? "": fields[f].substring(at+1);
			if(p.equals("p9sk1") || p.equals("p9pk1")){
				doms.add(new Dom(dom, p, getallkeys(io, p, dom)));
				sharedproto = true;
			}else if(log.debugging())
				log.debug("p9any: dom %s: unknown proto %s", dom, p);
		}
		if(!sharedproto)
			return "p9any: no protocol offered by server is supported";
		if(doms.size() == 0)
			return "p9any: server offered no authentication domains";
		if(log.logging()){
			for(Dom d : doms)
				log.info(String.format("dom: %s %s %s", d.dom, d.proto, d.keys!=null? d.keys.get(0): "none"));
		}

		// try the first domain for which we've got keys
		for(Dom d : doms){
			if(d.keys != null)
				return dosubproto(io, attrs, d, version);
		}

		// try the first domain and hope to get keys
		return dosubproto(io, attrs, doms.get(0), version);
	}

	String dosubproto(AuthIO io, Attrs attrs, Dom d, int version) throws LocalAuthErr, AuthenticationException {
		byte[] buf;
		String err;

		if(log.logging())
			log.info("selecting dom %s proto %s key %s", d.dom, d.proto, d.keys!=null? d.keys.get(0): "none");
		byte[] r = Strings.bytes(d.proto+" "+d.dom);
		buf = new byte[r.length+1];
		System.arraycopy(r, 0, buf, 0, r.length);
		buf[r.length] = (byte)0;
		io.write(buf, buf.length);
		if(version == 2){
			byte[] b = io.readn(3);
			if(b == null || b[0] != (byte)'O' || b[1] != (byte)'K' || b[2] != (byte)0)
				return "p9any: server did not send its OK";
			if(log.debugging())
				log.debug("OK");
		}
		P9sk1 p9sk1 = new P9sk1();
		err = p9sk1.init(io);
		if(err != null)
			return err;
		return p9sk1.interaction(io, attrs.copy().setattrs(String.format("proto=%s dom=%s", d.proto, Strings.quote(d.dom))));
	}

	ArrayList<Key> getallkeys(AuthIO io, String proto, String dom){
		try{
			return io.findkeys(null, String.format("proto=%s dom=%s", proto, Strings.quote(dom)));
		}catch(Exception e){	// don't care why: we only care that we didn't find it
			return null;
		}
	}

	public String keycheck(Key k){
		return null;
	}
}
