NAME
====

**box** - authenticated and confidential encryption

SYNOPSIS
========

	box new-identity [-name NAME]
	box add-peer -name NAME -key PUBLICKEY
	box list [-name NAME] [-show-secret]
	box seal [-from IDENTITY] -to PEER <MESSAGE >SEALED
	box open [-from PEER] [-to IDENTITY] <SEALED >MESSAGE

DESCRIPTION
===========

**box** is a utility for encrypting, authenticating, and decrypting data using
public and secret keys.

The keys used by box are stored in **$HOME/.box/**.  A *peer* is identified by
a public key; an *identity* is a public and secret key pair.  The default
identity is called **self**.

For example, Alice's public key would be stored at **$HOME/.box/self.public**
and her secret key at **$HOME/.box/self.secret**.  If Alice knows Bob's public
key, she could store his key at **$HOME/.box/bob.public**.

A payload can be sealed using **box seal [-from IDENTITY] -to PEER**, where the
payload is read from stdin and the sealed payload ie written to stdout.  If
IDENTITY is ommitted it's assumed to be self.  PEER can be ommitted, but can
also be self.  The sealed message will only be able to be opened by PEER; PEER
will be able to verify it was sent by IDENTITY.

A sealed payload can be unsealed using
**box open -from PEER [-to IDENTITY]**, where the sealed payload is read on
stdin and written on stdout.  The message is expected to be from the given
PEER.  If it's not, this command will fail.  IDENTITY is the expected receiver
of the box, and is used to decrypt it.  It defaults to self.

**box new-identity [-name NAME]** generates a new public/secret keypair with
the given name.  If no name is given it defaults to self.  If either key
already exists, it will fail.

**box add-peer -name NAME -key PUBLICKEY** adds PUBLICKEY to the box directory
under the given name as a peer.

**box list [-name NAME] [-show-secret]**, with no name, shows all the names and
public keys stored.  If **-show-secret** is given, secret keys will be shown
too.  If **NAME** is given, only the peer/identity of the given name is shown.

TODO
====

- Passwords?
- Benchmarks.
- File-aware syntax instead of just stdio.  Would allow some safety features
  such as making sure the whole file authenticates before moving the result to
  the target.
- License.
- Double check no branches/lookups depend on secrets.
