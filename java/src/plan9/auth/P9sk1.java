package plan9.auth;

/*
 * p9any/p9sk1 implementation
 *
 * a Java variant of Inferno's implementation in Limbo (MIT Licence)
 *
 * split off from com.vitanuova.auth.P9any
 * Java version revisions Copyright © 2012 Coraid Inc
 */

import java.util.Arrays;
import java.util.ArrayList;

import java.nio.channels.ByteChannel;
import java.io.IOException;

import plan9.lib.Attr;
import plan9.lib.Attrs;
import plan9.lib.Key;
import plan9.lib.Keys;
import plan9.lib.Packer;
import plan9.lib.Strings;
import plan9.lib.Base16;

import plan9.LogFactory;
import plan9.Log;

public class P9sk1 implements Authproto {

	static final Log log = LogFactory.logger(P9sk1.class);

	P9auth p9auth;

	public P9sk1(){}

	public String name(){
		return "p9sk1";
	}

	public String init(AuthIO io){
		if(p9auth == null)
			p9auth = new P9auth();
		return null;
	}

	public String interaction(AuthIO io, Attrs attrs) throws AuthenticationException, CryptoError {
		String role = attrs.findattrval("role");
		if(role == null)
			return "role not specified";
		if(!role.equals("client"))
			return "only client role supported";	// TO DO
		return p9sk1client(io);
	}

	//p9sk1:
	//	C->S:	nonce-C
	//	S->C:	nonce-S, uid-S, domain-S
	//	C->A:	nonce-S, uid-S, domain-S, uid-C, factotum-C
	//	A->C:	Kc{nonce-S, uid-C, uid-S, Kn}, Ks{nonce-S, uid-C, uid-S, K-n}
	//	C->S:	Ks{nonce-S, uid-C, uid-S, K-n}, Kn{nonce-S, counter}
	//	S->C:	Kn{nonce-C, counter}

	//asserts that uid-S and uid-C share new secret Kn
	//increment the counter to reuse the ticket.

	String p9sk1client(AuthIO io) throws AuthenticationException, CryptoError {

		//	C->S:	nonce-C
		byte[] cchal = new byte[P9auth.CHALLEN];
		Aids.memrandom(cchal, 0, P9auth.CHALLEN);
		io.write(cchal);

		//	S->C:	nonce-S, uid-S, domain-S
		byte[] trbuf;
		trbuf = io.readn(P9auth.TICKREQLEN);
		P9auth.Ticketreq tr = (new P9auth.Ticketreq()).unpack(new Packer(trbuf));
		if(log.debugging())
			log.debug("ticketreq: type=%d authid=%s authdom=%s chal= hostid=%s uid=%s",
				tr.rtype, tr.authid, tr.authdom, tr.hostid, tr.uid);

		// TO DO: iterate over keys
		Key mykey;
		try{
			mykey = io.findkey(null, String.format("dom=%s proto=p9sk1 user? !password?", tr.authdom));
		}catch(NeedKey e){
			return "can't find key: "+e.getMessage();
		}
		if(log.debugging())
			log.debug("mykey dom(%s) key(%s)", tr.authdom, mykey.fullText());
		byte[] ukey;
		String a;
		if((a = mykey.findattrval("!hex")) != null){
			ukey = (new Base16()).dec(a);
			if(ukey.length != P9auth.DESKEYLEN)
				return "p9sk1: invalid !hex key";
		}else	if((a = mykey.findattrval("!password")) != null)
			ukey = p9auth.passtokey(a);
		else
			return "no !password (or !hex) in key";

		//	A->C:	Kc{nonce-S, uid-C, uid-S, Kn}, Ks{nonce-S, uid-C, uid-S, K-n}
		String user = mykey.findattrval("user");
		if(user == null)
			user = Aids.user();	// shouldn't happen
		tr.rtype = P9auth.AuthTreq;
		tr.hostid = user;
		tr.uid = tr.hostid;	// not speaking for anyone else
		P9auth.TicketPair pair = gettickets(tr, ukey, mykey.findattrval("auth"));
		P9auth.Ticket tick = pair.known;
		if(tick.num != P9auth.AuthTc)
			return "p9sk1: could not get ticket: wrong key?";
		if(log.debugging())
			log.debug("ticket: num=%d chal= cuid=%s suid=%s key=%s", tick.num, tick.cuid, tick.suid, mykey);

		//	C->S:	Ks{nonce-S, uid-C, uid-S, K-n}, Kn{nonce-S, counter}
		P9auth.Authenticator ar = new P9auth.Authenticator(P9auth.AuthAc, tick.chal, 0);
		Packer p = new Packer(P9auth.TICKETLEN+P9auth.AUTHENTLEN);
		p.puta(pair.hidden);
		ar.pack(p, tick.key);
		io.write(p.array());

		//	S->C:	Kn{nonce-C, counter}
		byte[] sbuf = io.readn(P9auth.AUTHENTLEN);
		ar = (new P9auth.Authenticator()).unpack(new Packer(sbuf), tick.key);
		if(ar.num != P9auth.AuthAs || !Arrays.equals(ar.chal, cchal) || ar.id != 0)
			return "invalid authenticator from server";

		io.done(new Attrs(new Attr("cuid", tick.cuid),
				new Attr("suid", tick.suid),
				new Attr("cap", ""),
				new Attr("secret", (new Base16()).enc(P9auth.des56to64(tick.key)))));

		return null;
	}

	P9auth.TicketPair gettickets(P9auth.Ticketreq tr, byte[] key, String authsrv) throws CryptoError, AuthProtoErr, LocalAuthErr, RemoteAuthErr, AuthenticationException {
		P9auth.TicketPair ticketpair;

		if(tr.authdom.equals("ctlnod")){
			tr.hostid = tr.authid;
			ticketpair = p9auth.mktickets(tr, key);
			if(ticketpair != null)
				return ticketpair;
		}
		try{
			return getastickets(tr, key, authsrv);
		}catch(AuthenticationException e){
			// if it fails, have a last attempt at making our own
			ticketpair = p9auth.mktickets(tr, key);
			if(ticketpair != null)
				return ticketpair;
			throw e;
		}
	}

	P9auth.TicketPair getastickets(P9auth.Ticketreq tr, byte[] key, String authsrv) throws AuthProtoErr, LocalAuthErr, RemoteAuthErr {
		ByteChannel afd = Aids.authdial(null, tr.authdom, authsrv);
		P9auth.TicketPair ticketpair = p9auth._asgetticket(afd, tr, key);
		try{
			afd.close();
		}catch(IOException e){
			nullity();	// we don't care
		}
		return ticketpair;
	}

	public String keycheck(Key k){
		return null;
	}

	public void nullity(){}
}
