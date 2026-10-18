#ifndef DMCRYPTO_IOCTL_H
#define DMCRYPTO_IOCTL_H

#include "dmdrvi_ioctl.h"
#include "dmcrypto_types.h"

/*
 * The /dev/crypto node (the driver of dmcrypto, configured by a dmdevfs ini
 * section with driver_name=dmcrypto):
 *   read()   random bytes, from the entropy source the driver was given
 *            (-ENODEV when it has none, -EIO when it fails)
 *   write()  -EROFS
 *   ioctl    the commands below
 * Everything else - hashes, ciphers, key derivation - is the API of
 * dmcrypto.h, called directly (it is not a file interface).
 */

/** arg: dmcrypto_caps_t* - the loaded port's name and capabilities */
#define DMCRYPTO_IOCTL_GET_CAPABILITIES     (DMDRVI_IOCTL_CUSTOM_BASE + 0)

#endif /* DMCRYPTO_IOCTL_H */
