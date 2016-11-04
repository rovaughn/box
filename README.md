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

    - Use libsodium instead.  More up to date and provides scrypt.
    - Implement the other functions.
    - Option to read password from file (which will also allow testing the
      password functionality).
    - Better way to build and use scrypt?  The current method is pretty shoddy.
    - Also maybe a better way to select scrypt parameters.
    - Down the line, perhaps benchmarking.
    - Might actually be a good idea to get rid of some of the close's and free's
      and make some stuff more global for simplicity, since it's just a short
      lived utility that doesn't create memory/fd pressure.
    - Use the packed struct approach in more places.
    - Double check the bounds checking.  E.g. that the headers of files aren't
      too small.
    - Testing on mac.
    - More detailed documentation beyond synopsis.
    - Update README to reflect docs.
    - Add license and don't forget dependencies (scrypt, nacl).
    - Double check no branches/lookups depend on secrets and secret memory is
      cleared.
    - Raw binary mode.
    - Don't dump ciphertext to terminal unless explicit.  Maybe same for reading
      stdin from tty.
    - Util for encrypting/compressing tarballs and stuff.  Probably best off as
      a bash script.
    - Don't ask to confirm password when unboxing.

