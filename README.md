# dmcrypto

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/choco-technologies/dmcrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/choco-technologies/dmcrypto/actions/workflows/ci.yml)

Cryptographic primitives for DMOD: hashes (SHA-1/2), HMAC, PBKDF2, HKDF,
AES (CBC, CTR), AES-GCM and ChaCha20-Poly1305, random bytes - one interface
for every board, hardware-accelerated where the chip has an accelerator.

## Description

`dmcrypto` is only the interface (`include/dmcrypto.h`, shaped after PSA
Crypto): it validates the arguments and calls the port. The algorithms are
the **port's** (`dmcrypto_port`, `include/dmcrypto_port.h`); exactly one port
is loaded:

| Port | Code | Built for | Package |
|---|---|---|---|
| software | `src/port/sw` | every architecture dmod supports (found automatically) | `dmcrypto_port_sw-...-<arch_name>.zip` |
| hardware | `src/port/<family>` (`stm32f7`, `stm32f4`; shared: `stm32_common`) | every CPU family | `dmcrypto_port-...-<cpu_family>.zip` |

A hardware port uses the family's peripherals (CRYP, HASH, RNG) for what they
do and compiles in only the software algorithms it lacks, so no board carries
both. Which chip gets which package is in `src/port/*/mcus.txt` (`<cpu_name> hw|sw`,
an STM32F746 has no CRYP/HASH, an STM32F756 has): the release makes a tiny
manifest per chip from it (`ports-<cpu_name>.dmm`) and `manifest.dmm` includes the
one of the chip - so it has exactly one `dmcrypto_port`, under that one name.
**A new chip needs a line in its `mcus.txt`.**
`dmcrypto_get_capabilities()` says what the loaded port has and what of it the
hardware does. A caller that calls often and has checked its arguments can call
`dmcrypto_port_*` directly. See [docs/api-reference.md](docs/api-reference.md).

**Status:** the software port is complete (SHA-1/256/384/512, HMAC, PBKDF2, HKDF,
AES-CBC/CTR, AES-GCM, ChaCha20-Poly1305), tested against OpenSSL's results and
the RFCs' vectors (`tests/`). Random bytes come from an entropy source: the driver
(`/dev/crypto`, configured by `configs/board/<board>/crypto.ini`) reads the
node named by `entropy=` (dmrng's `/dev/rng`), or the application sets one with
`dmcrypto_set_entropy()` - dmcrypto depends on no RNG driver and has no
software fallback. The `crypto` tool (`crypto info | random | hash`) is in
`tools/crypto`. The hardware ports
(`stm32f7`, `stm32f4`) are still stubs: every function returns `-ENOTSUP`.

## Building

### Using CMake

```bash
mkdir -p build
cd build
cmake .. -DDMOD_CPU_FAMILY=sw          # or stm32f7, stm32f4: a hardware port
cmake --build .
```

Pass `-DDMOD_DIR=/path/to/local/dmod` to build against a local dmod checkout
instead of fetching `develop` from GitHub.

### Using Make

```bash
make DMOD_MODE=DMOD_MODULE DMOD_DIR=/path/to/dmod
```

## Testing

Tests are built automatically alongside the module (see `tests/`). Once built,
run them with `ctest`:

```bash
cd build
ctest --output-on-failure
```

`ctest` installs the test module's dependencies with `dmf-get` and then runs
it through `dmod_loader`. To run it manually instead:

```bash
export DMOD_DMF_DIR=$(pwd)/build/dmf
dmf-get install -d ${DMOD_DMF_DIR}/test_dmcrypto-local.dmd -y
dmod_loader build/dmf/test_dmcrypto.dmf
```

## Usage

<TBD>

This library module provides functions that can be used by other modules:

```c
#include "dmcrypto.h"
```

## API

| Function | Description |
|----------|-------------|
| `dmcrypto_create()` | Create a new `dmcrypto_t` instance. |
| `dmcrypto_destroy()` | Destroy an instance created by `_create()`. |
| `dmcrypto_is_valid()` | Check whether a handle is a valid instance. |

See [include/dmcrypto.h](include/dmcrypto.h) for the full
declarations and [docs/api-reference.md](docs/api-reference.md) for the
complete reference.

## Documentation

See the `docs/` directory:

- **[api-reference.md](docs/api-reference.md)** - Complete API documentation

View documentation using `dmf-man dmcrypto`.

## Hardware Port

This module ships two DMOD modules: the architecture-independent
`dmcrypto` and `dmcrypto_port`, which contains the
architecture-specific implementation. The active architecture is selected via
`DMOD_CPU_FAMILY` (default: `stm32f7`):

```bash
cmake .. -DDMOD_CPU_FAMILY=stm32f7
```

See [docs/port-implementation.md](docs/port-implementation.md) for how to add
another architecture. Port-specific files:

```
├── include/dmcrypto_port.h
├── src/port/
│   ├── CMakeLists.txt
│   └── stm32f7/
│       ├── config.cmake
│       └── port.c
└── dmcrypto_port.dmr
```
## Project Structure

```
dmcrypto/
├── docs/              # Documentation (markdown format)
├── include/           # Public headers
│   └── dmcrypto.h
├── src/
│   └── dmcrypto.c
├── tests/
│   ├── CMakeLists.txt
│   └── dmcrypto_test.c
├── CMakeLists.txt
├── Makefile
├── dmcrypto.dmr
└── manifest.dmm
```

## Author

Patryk Kubiak

## License

MIT
