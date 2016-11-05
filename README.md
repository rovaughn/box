box
===

A utility for encrypting/authenticating data in "boxes" with secret or public
keys.

Synopsis
--------

    box seal <plaintext >ciphertext
    box open <ciphertext >plaintext

TODO
----

    - Password from file?  Secret key from file?  And generate such a key.
    - Public-key encryption?  What would that interface look like?
    - Customize pwhash parameters?  Maybe an option for --sensitive.
    - Benchmarking for more optimizations wrt speed and memory.  E.g. mmap from
      file, fadvise, streaming.
    - Reduce variables' scope to the minimum.
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
    - Util for encrypting/compressing tarballs and stuff.  Probably best off as
      a bash script.
    - Ideally don't include extra zeros in boxes.
    - Make sure zeroes are cleared when reading in a file?
    - Make the nonce an optional parameter?  Could be good for network type
      stuff.  Maybe it'd be automatic for streaming stuff.
    - Maybe use AEAD for box metadata.

