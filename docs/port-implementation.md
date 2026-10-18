# Adding a port to dmcrypto

A port is `dmcrypto_port`: the module that implements every
`dmod_dmcrypto_port_api_declaration(...)` function of
`include/dmcrypto_port.h`. Exactly one is loaded at a time.

## The software port - `src/port/sw`

All algorithms in C, for any architecture. The release builds it for every
architecture dmod supports (read from dmod's `configs/arch`, so a new one
needs nothing here) and publishes it as `dmcrypto_port_sw`. Keep one source
file per algorithm family (`sw/sha2.c`, `sw/aes.c`, ...): a hardware port
compiles only the ones it needs.

## A hardware port - `src/port/<family>`

1. `src/port/<family>/config.cmake`: `DMOD_TOOLS_NAME` for the family (see
   `stm32f7`).
2. `src/port/<family>/port.c`: `dmod_init` / `dmod_deinit` and whatever
   differs from the other families. It must call something from dmod (e.g.
   `Dmod_Printf`) - a module without any import does not load.
3. Shared code of related families goes to `src/port/<vendor>_common`
   (`stm32_common`); it must **not** define `DMOD_ENABLE_REGISTRATION`
   (only the family's `port.c` does, or every registration is duplicated).
4. Add the sources in `src/port/CMakeLists.txt`.
5. Whatever the peripherals do not do (e.g. ChaCha20 on an STM32 - CRYP is AES
   only) is compiled in from `sw/`; say what the port has in
   `dmcrypto_port_get_capabilities` (`supported`, and `accelerated` for the
   hardware's share).

The release and CI find the families by their `port.c` (`sw` excluded) and
package each as `dmcrypto_port-<version>-<family>.zip`.

## Which chip gets which port

A family's chips differ in what they have (STM32F745/F746: no CRYP/HASH;
F756/F777: both). Each family lists its chips in `src/port/<family>/mcus.txt`:

    <cpu_name> hw|sw        # cpu_name: dmod-boot's DMOD_CPU_NAME, lower case

`hw` gets the family's hardware port, `sw` the software one. Chips of families
with no hardware port here (e.g. ESP32-S3) are listed in `src/port/sw/mcus.txt`
(all `sw`). `scripts/gen-ports-manifests.sh` turns the lists into
`ports-<cpu_name>.dmm`, one tiny manifest per chip with the single line

    dmcrypto_port <url of dmcrypto_port-v<version>-<cpu_family>.zip   # hw
    dmcrypto_port <url of dmcrypto_port_sw-v<version>-<arch_name>.zip # sw

The release uploads them to `vlatest`, `manifest.dmm` has
`$include .../vlatest/ports-<cpu_name>.dmm`, and `dmf-get` substitutes
`<cpu_name>` (dmod-boot passes DMOD_CPU_NAME). The entry is named
`dmcrypto_port` either way, so the dependency found in a package's `.dmd` is
satisfied by exactly one port. CI checks the lists (and that each family has
one). A chip that is in no list has no manifest: dmf-get warns "Failed to
include manifest ... ports-<cpu_name>.dmm" and then does not find
`dmcrypto_port` - add a line.

## Rules for a port

- Serialize your own hardware; callers need not.
- Arguments are already validated by `dmcrypto`; do not repeat that, and do
  not weaken it either - a direct caller has checked its own.
- No software fallback for the random source: `-EIO` when the hardware fails.
- Wipe secrets you copied (`dmcrypto_wipe`).
