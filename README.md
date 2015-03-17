#Styx and 9P2000 client and server support outside Inferno and Plan 9#

Styx® and 9P2000® are different names for the same file service protocol, called Styx by Inferno and 9P2000 (or just 9P) by Plan 9 from Bell Labs. We sometimes use the different names to distinguish the authentication scheme: public-key (Styx) or shared-secret (9P) but the scheme is actually separate from the protocol.

The protocol is connection-oriented, and maintains state on both client and server. It has only 14 simple messages, with a simple and obvious representation on the network (ie, decoding is straightforward).

In Inferno and Plan 9, the client-side interface is provided through ordinary system calls: mount, open/create, read/write, close. Outside those systems, library support is needed, and this project is intended to distribute and maintain some of those.

The first is a Java client, allowing concurrent access to a remote Styx server, including the use of Inferno public-key authentication. (Secure key storage must be provided separately.)
