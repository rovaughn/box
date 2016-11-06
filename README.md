box
===

A utility for encrypting/authenticating data in "boxes" with secret or public
keys.

Synopsis
--------

    **box seal** -password
    **box seal** -to <contact>
    **box seal** -from <identity>
    **box seal** -to <contact> -from <identity>
    **box open**
    **box add-contact** <name> <public-key>
    **box list-contacts**
    **box new-identity <name>**
    **box list-identities**

TODO
----

    - Password from file?
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
    - Build on osx.
    - Add license and don't forget dependencies (libsodium and readpass).
    - Double check no branches/lookups depend on secrets and secret memory is
      cleared.  Consider using the sensitive data malloc and stuff.
    - Util for encrypting/compressing tarballs and stuff.
    - Maybe use AEAD for box metadata.
    - Finish contact/identity system.

