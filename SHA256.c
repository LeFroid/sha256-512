// SHA 256 Implementation by Timothy Vaccarelli
// Based on the hashing algorithm details from http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
// and http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf

#include <stdlib.h>
#include <string.h>

#include "SHA256.h"
#include "config.h"

//K: The first thirty-two bits of the fractional parts of the cube roots of the first sixty-four primes.
const static uint32_t K[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}; 

// Utility functions
// Rotate x to the right by numBits
#define ROTR(x, numBits) ( (x >> numBits) | (x << (32 - numBits)) )

// Compression functions
#define Ch(x,y,z) ( (x & y) ^ ((~x) & z) )
#define Maj(x,y,z) ( (x & y) ^ (x & z) ^ (y & z) )

#define BigSigma0(x) ( ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22) )
#define BigSigma1(x) ( ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25) )

#define SmallSigma0(x) ( ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3) )
#define SmallSigma1(x) ( ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10) )

// SHA256 message schedule
// Calculate the Nth block of W
uint32_t *W256(int N, uint32_t *M)
{
    uint32_t *w = (uint32_t*) malloc(sizeof(uint32_t) * 64);
    uint32_t *mPtr = &M[(N * 16)];
    
    //printf("Message block %d : ", N);
    for (int i = 0; i < 16; ++i)
    {
        w[i] = *mPtr;
        ++mPtr;
        
    //printf("%" PRIx64 , w[i]);
    }
    //printf("\n");
    for (int i = 16; i < 64; ++i)
    {
        w[i] = SmallSigma1(w[i - 2]) + w[i - 7] + SmallSigma0(w[i - 15]) + w[i - 16];
    }
    return w;
}

// Step 1:
// Preprocesses a given message of l bits.
// Appends "1" to end of msg, then k 0 bits such that l + 1 + k = 448 mod 512
// and k is the smallest nonnegative solution to said equation. To this is appended
// the 64 bit block equal to the bit length l.
//char *preprocess(char *msg)
PaddedMsg preprocess256(uint8_t *msg, size_t len)
{    
    PaddedMsg padded;
    
    // resulting msg wll be multiple of 1024 bits
    //size_t len = strlen(msg);
    if (msg == NULL || len == 0)
    {
        padded.length = 0;
        padded.msg = NULL;
        return padded;
    }
    
    size_t l = len * 8;
    size_t k = (448 - ( (l + 1) % 512 )) % 512;
    //printf("k = %zu\n", k);
    //printf("l = %zu\n", l);
    //printf("l + k + 1 = %zu bits, %zu bytes\n", (l+k+1), ((l+k+1)/8));
    
    padded.length = ((l + k + 1) / 8) + 8;
    //printf("padded.length = %zu\n", padded.length);
    padded.msg = (uint8_t*) malloc(sizeof(uint8_t) * padded.length);
    memset(&padded.msg[0], 0, padded.length);
    for (size_t i = 0; i < len; ++i)
        padded.msg[i] = msg[i];
    // append to the binary string a 1 followed by k zeros
    padded.msg[len] = 0x80;
    
    // last 8 bytes reserved for length
    uint64_t bigL = l;
    endianSwap64(&bigL);
    memcpy(&padded.msg[padded.length - sizeof(uint64_t)], &bigL, sizeof(uint64_t));
    
    return padded;
}

// Step 2:
// Parse the padded message into N 512-bit blocks
// Each block separated into 32-bit words (therefore 16 per block)
// Returns an array of 8 32 bit words corresponding to the hashed value
uint32_t *get256Hash(PaddedMsg *p)
{
    size_t N = p->length / SHA256_MESSAGE_BLOCK_SIZE;
    //printf("Number of blocks = %zu\n", N);
    
    // initial hash value
    uint32_t h[SHA256_ARRAY_LEN] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };
    
#if MACHINE_BYTE_ORDER == LITTLE_ENDIAN
    // Convert byte order of message to big endian
    uint32_t *msg = ((uint32_t*)&p->msg[0]);
    for (int i = 0; i < N * 16; ++i)
        endianSwap32(msg++);
#endif

    for (size_t i = 0; i < N; ++i)
    {
        uint32_t T1, T2;
        // initialize registers
        uint32_t reg[SHA256_ARRAY_LEN];
        for (int i = 0; i < SHA256_ARRAY_LEN; ++i)
            reg[i] = h[i];
        
        uint32_t *w = W256(i, ((uint32_t*)(p->msg)));
        
        // Apply the SHA256 compression function to update registers
        for (int j = 0; j < 64; ++j)
        {   
            T1 = reg[7] + BigSigma1(reg[4]) + Ch(reg[4], reg[5], reg[6]) + K[j] + w[j];
            T2 = BigSigma0(reg[0]) + Maj(reg[0], reg[1], reg[2]);
            
            reg[7] = reg[6];
            reg[6] = reg[5];
            reg[5] = reg[4];
            reg[4] = reg[3] + T1;
            reg[3] = reg[2];
            reg[2] = reg[1];
            reg[1] = reg[0];
            reg[0] = T1 + T2;
        }
        
        // Compute the ith intermediate hash values 
        for (int i = 0; i < SHA256_ARRAY_LEN; ++i)
            h[i] += reg[i];
        
        free(w);
    }
    free(p->msg);
    
    // Now the array h is the hash of the original message M
    uint32_t *retVal = (uint32_t*) malloc(sizeof(uint32_t) * SHA256_ARRAY_LEN);
    memcpy(retVal, h, sizeof(uint32_t) * SHA256_ARRAY_LEN);
    return retVal;
}

/// Wrapper for hashing methods, up to caller to free the return value
uint32_t *SHA256Hash(uint8_t *input, size_t len)
{
    PaddedMsg paddedMsg = preprocess256(input, len);
    return get256Hash(&paddedMsg);
}

