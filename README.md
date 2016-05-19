# sha512
Implements the 512 bit Secure Hashing Algorithm 2 in a short number of functions.

# Code Example
```c
uint8_t msg[] = "abc";
uint64_t *digest = SHA512Hash(msg, 3);

// Print the digest as a hex string
for (int i = 0; i < HASH_ARRAY_LEN; ++i)
    printf("%016" PRIx64 , digest[i];
printf("\n");

free(digest);
```

# Motivation
Simply to refamiliarize myself with basic cryptography methods

# Building source code
To build the hashing functions as a library only, run:
```
/path/to/repo> mkdir build && cd build
/path/to/repo/build> cmake -DONLY_LIB=1 .. && make
```
To build the executable file, run:
```
/path/to/repo> mkdir build && cd build
/path/to/repo/build> cmake .. && make
```

