NAME
====

**box** - authenticated and confidential encryption

SYNOPSIS
========

	box new-identity [-name NAME]
	box add-peer -name NAME -key PUBLICKEY
	box list [NAME ...]
	box seal [-from IDENTITY] -to PEER <MESSAGE >SEALED
	box open [-from PEER] [-to IDENTITY] <SEALED >MESSAGE

DESCRIPTION
===========

**box** is a utility for encrypting, authenticating, and decrypting data using
public and secret keys.

Public and secret keys are stored in **$HOME/.box/**, though this can be
overriden by setting the **$BOXDIR** environment variable.  **Identities** and
**peers** are stored in this directory.  An identity is associated with a
secret key and public key, while a peer is only associated with a public key.
The default identity is called **self**.

For example, Alice's secret keypair representing her identity would be stored
at **/home/alice/.box/self**.  If Alice knows Bob's public key, she would store
his key at **$HOME/.box/bob**.  You do not need to edit these yourself; keys
are managed using the **box** tool.

A payload can be sealed using **box seal [-from IDENTITY] -to PEER**, where the
payload is read from stdin and the sealed payload ie written to stdout.  If
IDENTITY is ommitted it's assumed to be self.  PEER is required, but can also
be self.  The sealed message will only be able to be opened by PEER; PEER will
be able to verify it was sent by IDENTITY.

A sealed payload can be unsealed using **box open -from PEER [-to IDENTITY]**,
where the sealed payload is read on stdin and written on stdout.  The message
is expected to be from the given PEER.  If it's not, this command will fail.
IDENTITY is the expected receiver of the box, and is used to decrypt it.  It
defaults to self.

**box new-identity [-name NAME]** generates a new public/secret keypair with
the given name.  If no name is given it defaults to self.  If either key
already exists, it will fail.

**box add-peer -name NAME -key PUBLICKEY** adds PUBLICKEY to the box directory
under the given name as a peer.  PUBLICKEY is hex-encoded.

**box list [NAME ...]**, shows the name, type, and public key (hex-encoded)
associated with the given names.  If no names are given, all stored entities
will be listed.

TODO
====

- Passwords?
- Benchmarks.
- File-aware syntax instead of just stdio.  Would allow some safety features
  such as making sure the whole file authenticates before moving the result to
  the target.
- License.
- Maybe some fuzzing would be in order.
