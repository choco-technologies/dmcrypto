# crypto

The crypto of the shell, on dmcrypto.

```
crypto info [DEVICE]          the port and what it has (default /dev/crypto)
crypto random N               N random bytes (1..1024) in hex
crypto hash ALG FILE          the digest of a file: sha1 sha256 sha384 sha512
crypto hash ALG -s TEXT       ... of a text
```

```
> crypto info
port: sw
  SHA-1                  software
  ...
  random                 software
> crypto hash sha256 -s abc
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
> crypto random 16
9f3ac1...
```

`info` needs the `/dev/crypto` node (dmcrypto's driver, configured by an ini
section: `configs/board/<board>/crypto.ini`). `random` needs an entropy source:
the driver's `entropy=` (dmrng's `/dev/rng` on the STM32F746G-DISCO); without
one it says so - there is no software fallback.
