// SHA 512 Implementation by Timothy Vaccarelli
// Based on the hashing algorithm details from http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
// and http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf

#ifndef __SHA512_H_
#define __SHA512_H_

#include <inttypes.h>
#include <stdint.h>

#include "SHACommon.h"

#define SHA512_MESSAGE_BLOCK_SIZE 128
#define SHA512_HASH_SIZE 64
#define HASH_ARRAY_LEN 8
#define MAX_VAL 0xFFFFFFFFFFFFFFFFLLU

/// Preprocesses the given message of len bytes
PaddedMsg preprocess(uint8_t *msg, size_t len);

/// Returns the sha-512 hash corresponding to the padded message: Return value must be free()'d
uint64_t *getHash(PaddedMsg *p);

/// Wrapper for hashing methods, up to caller to free the return value
uint64_t *SHA512Hash(uint8_t *input, size_t len);

#endif //__SHA512_H_
