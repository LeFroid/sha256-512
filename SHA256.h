// SHA 256 Implementation by Timothy Vaccarelli
// Based on the hashing algorithm details from http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
// and http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf

#ifndef __SHA256_H_
#define __SHA256_H_

#include <inttypes.h>
#include <stdint.h>

#include "SHACommon.h"

// Message block size measured in bytes
#define SHA256_MESSAGE_BLOCK_SIZE 64 
#define SHA256_ARRAY_LEN 8

/// Preprocesses the given message of len bytes
PaddedMsg preprocess256(uint8_t *msg, size_t len);

/// Returns the sha-256 hash corresponding to the padded message: Return value must be free()'d
uint32_t *get256Hash(PaddedMsg *p);

/// Wrapper for hashing methods, up to caller to free the return value
uint32_t *SHA256Hash(uint8_t *input, size_t len);

#endif //__SHA512_H_
