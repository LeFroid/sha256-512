// SHA 512 Implementation by Timothy Vaccarelli
// Based on the hashing algorithm details from http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
// and http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SHA512.h"
#include "SHA256.h"

typedef enum Mode
{
    MODE_256 = 0x01,
    MODE_512 = 0x02,
    MODE_512_256 = 0x04,
    MODE_ALL = (MODE_256 | MODE_512 | MODE_512_256),
} Mode;

Mode progMode = MODE_ALL;

/// Prints the checksum of the given file
void getChecksum(char *filename)
{
    if (filename == NULL)
        return;
        
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        printf("Error: Invalid file.\n");
        return;
    }
    
    long int fileSize = 0;
    
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *fileContents = (char*) malloc(sizeof(char) * fileSize);
    if (fileContents == NULL)
    {
        printf("Error: Unable to allocate memory to read file contents.\n");
        fclose(file);
        return;
    }
    
    size_t amountRead = fread(fileContents, 1, fileSize, file);
    if (amountRead != fileSize)
    {
        printf("Error: Unable to read entire file.\n");
        free(fileContents);
        fclose(file);
        return;
    }
    fclose(file);
    
    if (progMode & MODE_512)
    {
        uint64_t *checksum = SHA512Hash((uint8_t*)fileContents, fileSize);
        for (int i = 0; i < HASH_ARRAY_LEN; ++i)
            printf("%016" PRIx64 , checksum[i]);
        printf("\n");
        free(checksum);
    }

    if (progMode & MODE_256)
    {
        uint32_t *checksum2 = SHA256Hash((uint8_t*)fileContents, fileSize);
        for (int i = 0; i < SHA256_ARRAY_LEN; ++i)
            printf("%08" PRIx32 , checksum2[i]);
        printf("\n");
        free(checksum2);
    }

    if (progMode & MODE_512_256)
    {
        uint64_t *checksum = SHA512Hash((uint8_t*)fileContents, fileSize);
        for (int i = 0; i < HASH_ARRAY_LEN/2; ++i)
            printf("%016" PRIx64 , checksum[i]);
        printf("\n");
        free(checksum);
    }
    
    free(fileContents);
}

/// Prints the program options
void printOptions(char *arg0)
{
    printf("Usage: %s [OPTION or STRING]\n", arg0);
    printf("Calculate the SHA-512, SHA-512/256 or SHA-256 hashes of an input string, or the checksum of a given file.\n\n");
    printf("Options:\n");
    printf("-f, --file [FILENAME] Calculate the SHA-512, SHA-512/256 & SHA-256 checksums of the file.\n");
    printf("-m, --mode [MODE] Calculates only the SHA256 digest with mode = 256, or only the SHA512 digest with mode = 512, or the truncated variant SHA512/256 with mode = 512_256\n");
    printf("-h, --help Print command line options\n\n");   
}

/// Hashes the input string received by the program
void hashInput(int argc, int inputPos, char **argv)
{
    size_t inputLen = 0;
    for (int i = inputPos; i < argc; ++i)
        inputLen += strlen(argv[i]) + 1;
    char *argStr = (char*) malloc(sizeof(char) * inputLen);
    size_t pos = 0;
    for (int i = inputPos; i < argc; ++i)
    {
        size_t argLen = strlen(argv[i]);
        memcpy(&argStr[pos], argv[i], argLen);
        pos += argLen;
        if (pos + 1 < inputLen)
            argStr[pos++] = ' ';
    }
    argStr[inputLen - 1] = '\0';
    
    // Calculate a hash of argStr
    if (progMode & MODE_512)
    {
        uint64_t *argHash = SHA512Hash((uint8_t*)argStr, strlen(argStr));
        printf("SHA-512 hash of command line input: \n");
        for (int i = 0; i < HASH_ARRAY_LEN; ++i)
            printf("%016" PRIx64 , argHash[i]);
        printf("\n");
        free(argHash);
    }
    if (progMode & MODE_256)
    {
        uint32_t *argHash2 = SHA256Hash((uint8_t*)&argStr[0], strlen(argStr));
        printf("SHA-256 hash of command line input: \n");
        for (int i = 0; i < SHA256_ARRAY_LEN; ++i)
            printf("%08" PRIx32 , argHash2[i]);
        printf("\n");
        free(argHash2);
    }
    if (progMode & MODE_512_256)
    {
        uint64_t *argHash3 = SHA512_256Hash((uint8_t*)argStr, strlen(argStr));
        printf("SHA-512/256 hash of command line input: \n");
        for (int i = 0; i < HASH_ARRAY_LEN/2; ++i)
            printf("%08" PRIx64 , argHash3[i]);
        printf("\n");
        free(argHash3);
    }
    
    free(argStr);
}

// Hashes the argument given, or if "-f" flag is used, hashes the contents of a given file
int main(int argc, char **argv)
{
    if (argc > 1)
    {
        int inputPos = 1;
        char *flag = argv[1];
        if (flag[0] == '-')
        {
            int i;
            int argNumWithFile = -1;
            for (i = 1; i < argc; ++i)
            {
                flag = argv[i];
                char c = (flag[1] == '-') ? flag[2] : flag[1];
                switch (c)
                {
                    // handle argv[2] as a file
                    case 'f':
                        if (argc > i + 1)
                            argNumWithFile = i + 1;
                        break;
                    // change mode of operation
                    case 'm':
                        if (argc > i + 1)
                        {
                            char *str256 = "256";
                            char *str512 = "512";
			    char *str512_256 = "512_256";
                            if (strncmp(argv[i + 1], str256, 3) == 0)
                                progMode = MODE_256;
                            if (strncmp(argv[i + 1], str512, 3) == 0)
                                progMode = MODE_512;
                            if (strncmp(argv[i + 1], str512_256, 7) == 0)
                                progMode = MODE_512_256;

                            if (argc > i + 2)
                                inputPos = i + 2;
                        }
                        break;
                    // print options
                    case 'h':
                        printOptions(argv[0]);
                        break;
                    default:
                        break;
                }
            }
            if (argNumWithFile > -1)
            {
                getChecksum(argv[argNumWithFile]);
                inputPos = argc + 1;
            }
        }
        
        if (inputPos < argc)
            hashInput(argc, inputPos, argv);
    }
    else
        printOptions(argv[0]);

    return 0;
}
