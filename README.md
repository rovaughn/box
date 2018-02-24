## NAME

**box** - authenticated and confidential encryption

## SYNOPSIS

	box new-identity [-name NAME]
	box add-peer -name NAME -key PUBLICKEY
	box list [-only-key] [NAME ...]
	box seal [-from IDENTITY] -to PEER <MESSAGE >SEALED
	box open -from PEER [-to IDENTITY] <SEALED >MESSAGE

## INSTALL

	go get github.com/rovaughn/box

## EXAMPLE

Let's say Alice wants to send a secret file to Bob.  Alice wants to make sure
the encrypted file can only be read by Bob.  Bob wants to make sure that it was
actually Alice that sent it.

Alice and Bob start by creating new identities:

	bob$ box new-identity
	bob$ box list
	NAME  TYPE      PUBLIC KEY
	self  identity  97af76065f8d6fedba16a43120b0f02cf19787b9f8cbea111162f5324824e543

	alice$ box new-idenitty
	alice$ box list
	NAME  TYPE      PUBLIC KEY
	self  identity  b3dba84ec8805b3ee6953311a341426483b4c52db37634c540a388ffae2fd32e

These public keys represent Alice and Bob's respective identities.  Alice and
Bob can exchange these keys over an insecure channel like SMS or email.

Next Alice and Bob add each other's public keys as peers:

	bob$ box add-peer -name alice -key b3dba84ec8805b3ee6953311a341426483b4c52db37634c540a388ffae2fd32e
	bob$ box list
	NAME   TYPE      PUBLIC KEY
	self   identity  97af76065f8d6fedba16a43120b0f02cf19787b9f8cbea111162f5324824e543
	alice  peer      b3dba84ec8805b3ee6953311a341426483b4c52db37634c540a388ffae2fd32e

	alice$ box add-peer -name bob -key 97af76065f8d6fedba16a43120b0f02cf19787b9f8cbea111162f5324824e543
	alice$ box list
	NAME  TYPE      PUBLIC KEY
	self  identity  b3dba84ec8805b3ee6953311a341426483b4c52db37634c540a388ffae2fd32e
	bob   peer      97af76065f8d6fedba16a43120b0f02cf19787b9f8cbea111162f5324824e543

Now Alice can seal a message and send it to Bob:

	alice$ echo 'attack at dawn' | box seal -to bob >message.sealed

	bob$ box seal -from alice <message.sealed
	attack at dawn

## REFERENCE

	box new-identity [-name NAME]

Generate a new secret key and store it as an identity with the given NAME.  If
the identity already exists this command will fail.

	box add-peer -name NAME -key PUBLICKEY

Store the given hex-encoded public key as a peer with the given NAME.  If the
peer already exists this command will fail.

	box list [-only-key] [NAME ...]

List stored peers/identities and their public keys.  If no NAMEs are given, all
entities are shown.  If -only-key is provided, nothing but public keys are
shown, which can be useful for scripts/copy pasting.

	box seal [-from IDENTITY] -to PEER <MESSAGE >SEALED

Read a payload from stdin, seal it with IDENTITY's secret key and PEER's public
key, and write it to stdout.  If IDENTITY is not provided, it's assumed to be
"self."

	box open -from PEER [-to IDENTITY] <SEALED >MESSAGE

Read a sealed payload from stdin, unseal it with IDENTITY's secret key and
PEER's public key, and write it to stdout.  If IDENTITY is not provided, it's
assumed to be "self."

## BOX DIRECTORY

Public and secret keys are stored in **$HOME/.box/**, though this can be
overriden by setting the **$BOXDIR** environment variable.  **Identities** and
**peers** are stored in this directory.  An identity is associated with a
secret key and public key, while a peer is only associated with a public key.
The default identity is called **self**.

For example, Alice's secret keypair representing her identity would be stored
at **/home/alice/.box/self**.  If Alice knows Bob's public key, she would store
his key at **/home/alice/.box/bob**.  You do not need to edit these yourself;
keys are managed using the **box** tool.

## TODO/IDEAS

- Generate an identity from a password (hash with argon2)
- Benchmarks.
- If `-from` is missing with `open`, the public key could automatically be
  determined by testing all keys.
- When `-from` and `-to` are the same, could be faster to just use secretbox.
- `-from anonymous` (create an ephemeral identity and send the public key with
  the sealed message; only the receiver can decrypt it but it is not signed as
  coming from any particular identity.
- `-to anyone` essentially amounts to signing the payload (possibly with
  ed25519 for speed) and not encrypting it.
- File-aware syntax instead of just stdio.  Would allow some safety features
  such as making sure the whole file authenticates before moving the result to
  the target.
- License.
- Maybe some fuzzing would be in order.
