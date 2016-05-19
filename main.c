// SHA 512 Implementation by Timothy Vaccarelli
// Based on the hashing algorithm details from http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
// and http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SHA512.h"

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
    
    uint64_t *checksum = SHA512Hash((uint8_t*)fileContents, fileSize);
    for (int i = 0; i < HASH_ARRAY_LEN; ++i)
        printf("%016" PRIx64 , checksum[i]);
    printf("\n");
    
    free(fileContents);
    free(checksum);
}

/// Prints the program options
void printOptions(char *arg0)
{
    printf("Usage: %s [OPTION or STRING]\n", arg0);
    printf("Calculate the SHA-512 hash of an input string, or the checksum of a given file.\n\n");
    printf("Options:\n");
    printf("-f, --file [FILENAME] Calculate the SHA-512 checksum of the file.\n");
    printf("-h, --help Print command line options\n\n");   
}

/// Hashes the input string received by the program
void hashInput(int argc, char **argv)
{
    size_t inputLen = 0;
    for (int i = 1; i < argc; ++i)
        inputLen += strlen(argv[i]) + 1;
    char *argStr = (char*) malloc(sizeof(char) * inputLen);
    size_t pos = 0;
    for (int i = 1; i < argc; ++i)
    {
        size_t argLen = strlen(argv[i]);
        memcpy(&argStr[pos], argv[i], argLen);
        pos += argLen;
        if (pos + 1 < inputLen)
            argStr[pos++] = ' ';
    }
    argStr[inputLen - 1] = '\0';
    
    // Calculate a hash of argStr
    uint64_t *argHash = SHA512Hash((uint8_t*)argStr, strlen(argStr));
    printf("SHA-512 hash of command line input: \n");
    for (int i = 0; i < HASH_ARRAY_LEN; ++i)
        printf("%016" PRIx64 , argHash[i]);
    printf("\n");
    
    free(argStr);
    free(argHash);
}

// Hashes the argument given, or if "-f" flag is used, hashes the contents of a given file
int main(int argc, char **argv)
{
    if (argc > 1)
    {
        char *flag = argv[1];
        if (flag[0] == '-')
        {
            char c = (flag[1] == '-') ? flag[2] : flag[1];
            switch (c)
            {
                // handle argv[2] as a file
                case 'f':
                    getChecksum(argv[2]);
                    break;
                // print options
                case 'h':
                    printOptions(argv[0]);
                    break;
                default:
                    break;
            }
        }
        else
            hashInput(argc, argv);
    }
    else
        printOptions(argv[0]);

    return 0;
}
