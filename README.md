box
===

A utility for encrypting/authenticating data in "boxes".

`box seal -password` asks for a password and then seals stdin into a box that
can only be opened by entering the same password.

`box seal -password-file <file>` is the same as `-password` but reads the
password from the given file.

`box seal -to <receiver>` seals stdin into a box that can only be opened by
`<receiver>`.

`box seal -from <sender>` puts stdin unencrypted into a box where a receiver
can verify it came from `<sender>`.

`box seal -from <sender> -to <receiver>` seals stdin into a box that can only
be opened by `<receiver>`, and `<receiver>` can verify it came from `<sender>`.

`box open` opens a box from stdin.

`box new-identity` creates a new identity with public and secret keys.  It
prints out the public identity which can be used by `box add-contact` to add
your identity to their contact list.

`box list-identities` lists your public identities and `box list-contacts` lists
your known contacts.

TODO
----

- Maybe rename identities to senders and contacts to receivers.  Would keep
  naming schemes more consistent.  And perhaps a sender is automatically a
  receiver.
- Password from file?  Maybe as long as /dev/tty can be hijacked.
- Customize pwhash parameters?  Maybe just a -sensitive option.
- Benchmarking for more optimizations wrt speed and memory.  E.g. mmap,
  fadvise, streaming.  Don't forget how streaming might affect correctness.
  Also note some of the algorithms can decrypt/encrypt in place.
- File specific syntax might make it easier to box (e.g. automatically
  creating file blah -> blah.box and vice versa and option to delete
  originally like compression utils do).  Also could be safer cause it could
  be atomic.  If an unboxing fails it won't write the file at all.  Plus
  knowing the size of the file ahead of time could be safer and avoids
  keeping sensitive things in memory.
- Double check the bounds checking.  E.g. that the headers of files aren't
  too small.
- Add license and don't forget dependencies (libsodium and readpass).
- Double check no branches/lookups depend on secrets and secret memory is
  cleared.  Consider using the sensitive data malloc and stuff.
- Util for encrypting/compressing tarballs and stuff.
- Maybe use AEAD for box metadata.
- Finish contact/identity system.
- Install script.
- Set permissions for .box-home to be more restrictive.
- Indexes, esp unique indexes.  Might require better error reporting.
- Rename .box-home?  Maybe ~/.boxdb.

