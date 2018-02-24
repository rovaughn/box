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

EXAMPLE
=======

Let's say Alice wants to send a secret file to Bob.  Alice wants to make sure
the encrypted file can only be read by Bob.  Bob wants to make sure that it was
actually Alice that sent it.

Alice and Bob start by creating new identities:

	bob$ box new-identity
	bob$ box list
	name  type      public key
	----  --------  ----------------------------------------------------------------
	self  identity  97af76065f8d6fedba16a43120b0f02cf19787b9f8cbea111162f5324824e543

	alice$ box new-idenitty
	alice$ box list
	name  type      public key
	----  --------  ----------------------------------------------------------------
	self  identity  b3dba84ec8805b3ee6953311a341426483b4c52db37634c540a388ffae2fd32e

These public keys represent Alice and Bob's respective identities.  Alice and
Bob can now exchange these public keys (it's ok if an eavesdropper gets ahold
of a public key).

Next Alice and Bob add each other's public keys as peers:

	bob$ box add-peer -name alice -key b3dba84ec8805b3ee6953311a341426483b4c52db37634c540a388ffae2fd32e
	bob$ box list
	name   type      public key
	----   --------  ----------------------------------------------------------------
	self   identity  97af76065f8d6fedba16a43120b0f02cf19787b9f8cbea111162f5324824e543
	alice  peer      b3dba84ec8805b3ee6953311a341426483b4c52db37634c540a388ffae2fd32e

	alice$ box add-peer -name bob -key 97af76065f8d6fedba16a43120b0f02cf19787b9f8cbea111162f5324824e543
	alice$ box list
	name  type      public key
	----  --------  ----------------------------------------------------------------
	self  identity  b3dba84ec8805b3ee6953311a341426483b4c52db37634c540a388ffae2fd32e
	bob   peer      97af76065f8d6fedba16a43120b0f02cf19787b9f8cbea111162f5324824e543

Now Alice can seal a message and send it to Bob:

	alice$ echo 'attack at dawn' | box seal -to bob >message.sealed

	bob$ box seal -from alice <message.sealed
	attack at dawn

BOX DIRECTORY
=============

Public and secret keys are stored in **$HOME/.box/**, though this can be
overriden by setting the **$BOXDIR** environment variable.  **Identities** and
**peers** are stored in this directory.  An identity is associated with a
secret key and public key, while a peer is only associated with a public key.
The default identity is called **self**.

For example, Alice's secret keypair representing her identity would be stored
at **/home/alice/.box/self**.  If Alice knows Bob's public key, she would store
his key at **/home/alice/.box/bob**.  You do not need to edit these yourself;
keys are managed using the **box** tool.

TODO
====

- Passwords?
- Benchmarks.
- File-aware syntax instead of just stdio.  Would allow some safety features
  such as making sure the whole file authenticates before moving the result to
  the target.
- License.
- Maybe some fuzzing would be in order.
