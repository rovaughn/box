box
===

A very simple utility for symmetrically encrypting and authenticating data
written with NaCl's secretbox.

Example usage with a keyfile:

    $ box-generate-key >keyfile
    $ cat keyfile
    792593245fe139b126f5a909d1d4a6270f096b82940caed448767b949388236c
    $ echo 'secret data' | box keyfile >encrypted-data
    $ hexdump encrypted-data
    0000000 8bfd 087f ddbb 60d4 29bf a1e2 6587 8644
    0000010 405c cadd 5f82 ea4d 4947 9a9f bb3d d5a8
    0000020 f799 7e5b 52d0 d145 735a e222 b8b1 6fda
    0000030 74a3 bfac                              
    0000034
    $ unbox keyfile <encrypted-data
    secret data

Example usage with a password:
    
    $ echo 'secret data' | box >encrypted-data
    Password: alice
    $ hexdump encrypted-data
    0000000 76b3 c9b3 92b4 9742 5acd e274 fd15 e19f
    0000010 4803 b961 afa7 9b6f b1d7 6808 b82f 5d09
    0000020 bbbf b0d4 9ce4 177e 0dd9 6ddc 04e9 fb0a
    0000030 7023 f94e                              
    0000034
    $ unbox <encrypted-data
    Password: alice (not actually echoed to terminal)
    secret data 
    $ unbox <encrypted-data
    Password: bill (not actually echoed to terminal)
    Couldn't unbox.

