NAME
----

    **nacl** - simple command line interface to the
    [https://nacl.cr.yp.to](NaCl: Networking and Cryptography Library).

SYNOPSIS
--------

    **nacl box keypair**
    **nacl box make**
    **nacl box open**
    **nacl box beforenm**
    **nacl box afternm**
    **nacl box open afternm**
    **nacl sign keypair**
    **nacl sign create**
    **nacl sign open**
    **nacl secretbox make [--password keyfile] [file]**
    **nacl secretbox open [--password keyfile] [file]**
    **nacl key** - generate a 256-bit hex key
    **nacl stream new**
    **nacl stream xor**
    **nacl auth**
    **nacl auth verify**
    **nacl onetimeauth**
    **nacl onetimeauth verify**
    **nacl hash**
    **nacl random**

TODO
----

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

