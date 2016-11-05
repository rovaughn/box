NAME
----

    **nacl** - simple command line interface to the
    [https://nacl.cr.yp.to](NaCl: Networking and Cryptography Library).

SYNOPSIS
--------

    **nacl box-keypair -p PUBLICKEY -s SECRETKEY**
    **nacl box -p PUBLICKEY -s SECRETKEY [-i IN] [-o OUT]**
    **nacl box-open -p PUBLICKEY -s SECRETKEY [-i IN] [-o OUT]**
    **nacl box-beforenm -p PUBLICKEY -s SECRETKEY -k KEY**
    **nacl box-afternm -k KEY [-i IN] [-o OUT]**
    **nacl box-open-afternm -k KEYFILE [-i IN] [-o OUT]**
    **nacl sign-keypair**
    **nacl sign-create**
    **nacl sign-open**
    **nacl secretbox {-p | -k KEYFILE} [-i IN] [-o OUT]**
    **nacl secretbox-open {-p | -k KEYFILE} [i IN] [-o OUT]**
    **nacl secretbox-key -k KEYFILE**
    **nacl stream new**
    **nacl stream xor**
    **nacl auth**
    **nacl auth verify**
    **nacl onetimeauth**
    **nacl onetimeauth verify**
    **nacl hash [-i IN] [-o OUT]**
    **nacl random -n BYTES [-o OUT]**

TODO
----

    - Implement the other functions.
    - Option to read password from file (which will also allow testing the
      password functionality).
    - Choose pwhash parameters?
    - Down the line, perhaps benchmarking.  At least do this before any other
      optimization like mmap.
    - Might actually be a good idea to get rid of some of the close's and free's
      and make some stuff more global for simplicity, since it's just a short
      lived utility that doesn't create memory/fd pressure.
    - Reduce variables' scope to the minimum.
    - Double check the bounds checking.  E.g. that the headers of files aren't
      too small.
    - Testing on osx.
    - More detailed documentation beyond synopsis.
    - Update README to reflect docs.
    - Add license and don't forget dependencies (libsodium).
    - Double check no branches/lookups depend on secrets and secret memory is
      cleared.
    - Raw binary option.
    - Don't dump ciphertext to terminal unless explicit.  Maybe same for reading
      stdin from tty (i.e. don't read something that's probably binary like
      ciphertext from stdin).
    - Util for encrypting/compressing tarballs and stuff.  Probably best off as
      a bash script.
    - Don't ask to confirm password when unboxing.
    - Any good reasons to store length in boxes?  Would make it somewhat more
      efficient at the cost of slightly bigger box size.  Would also make it
      possible to pack multiple boxes in a row which could more or less give us
      packet-oriented streaming for free.
    - Ideally don't include extra zeros in boxes.
    - Make sure zeroes are cleared when reading in a file?
    - Make the nonce an optional parameter?  Could be good for network type
      stuff.
    - Do we really need the beforenm/afternm stuff?  Maybe we only use that in
      a streaming interface.

