[![compilation](https://github.com/libecc/openpgp-libecc/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/libecc/openpgp-libecc/actions/workflows/tests.yml)

# OpenPGP libecc

Author:
   - Marian KECHLIBAR (<mailto:marian.kechlibar@circletech.net>)

Contributor:
   - Ryad BENADJILA (<mailto:ryadbenadjila@gmail.com>)

This software is licensed under a dual BSD and GPL v2 license, see the [LICENSE](LICENSE) file at the root folder of the project.

## About the project

This repository implements a basic API based upon [libecc](https://github.com/libecc/libecc) to handle
OpenPGP elliptic curve cryptography signature and ECDH variants of key exchange algorithms: all the exported signature,
verification and symmetric secret derivation functions are exposed in the header file [src/openpgp_layer.h](src/openpgp_layer.h).

OpenPGP ECDSA and EdDSA signatures are supported, and ECDH over prime curves as well as legacy Curve25519 (please check
the [OpenPGP RFC](https://datatracker.ietf.org/doc/html/rfc4880) for more insights on the signature and encryption of
PGP messages).

The current repository does not aim at implementing a full-featured OpenPGP client, but rather at implementing over libecc
the ECC cryptographic part of OpenPGP (that can serve of a basis for a client). Many missing pieces must be added to be able to
encrypt/sign messages: the serialization and deserialization parts (here, messages are supposed to be well-formatted), the symmetric
encryption primitives, etc. The project is delivered "as is", it might (or might not) evolve towards a more complete PoC: contributions are welcome!

## Compiling the project

In order to compile the project, you will first need to fetch libecc: this should be automatically done using the Makefile. A simple `make` should
trigger the following error:

```
$ make
Error: you asked for compilation while no libecc is present! Please install libecc using make install_libecc and run your make command again.
```

Then, executing `make install_libecc` should fetch the proper repository:
```
$ make install_libecc 
[+] Cloning the libecc repository
...
```

After this, compiling the project is as simple as `make`:
```
$ make
[+] Compiling libecc
...
[+] Compiling openpgp-libecc
```

A `build/openpgp_test` binary should then be available, and executing it will check static test vectors from
[src/test/openpgp_layer_test_vectors.h](src/test/openpgp_layer_test_vectors.h) (produced using a regular OpenPGP client).

```
$ ./build/openpgp_test 
[+] ECDH for KOpenPGPLayerTestVector_Nist384_1 is OK
[+] ECDH for KOpenPGPLayerTestVector_Nist521_1 is OK
[+] ECDH for KOpenPGPLayerTestVector_Curve25519Legacy_1 is OK
[+] ECDH for KOpenPGPLayerTestVector_Curve25519Legacy_2 is OK
[+] ECDSA for KOpenPGPLayerParams_ECDSA_1 is OK
[+] ECDSA for KOpenPGPLayerParams_ECDSA_2 is OK
[+] ECDSA for KOpenPGPLayerParams_ECDSA_3 is OK
[+] ECDSA for KOpenPGPLayerParams_ECDSA_4 is OK
[+] ECDSA for KOpenPGPLayerParams_ECDSA_5 is OK
[+] EdDSA for KOpenPGPLayerParams_EdDSA_1 is OK
[+] EdDSA for KOpenPGPLayerParams_EdDSA_2 is OK
```
