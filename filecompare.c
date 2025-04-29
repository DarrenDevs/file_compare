/**
 * @file filecompare.c
 * @author Darren Baker
 * @date 12-15-2024
 * @brief Program that demonstrates the use of the SHA256 hashing algorithm in
 *        the OpenSSL library to determine whether two files whose names are 
 *        given as command line arguments are identical.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define HASH_LENGTH 32 // SHA256 32-byte hash

//calculate the SHA256 hash
int calcSha256(const char *filename, unsigned char *hash) {
    FILE *file = fopen(filename, "rb"); //Open file in binary read mode
    if (!file) { // Check to see if there was an error in opening the file
        perror("Error opening file");
        return 0;
    }

    // Create a new digest context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { // Check to see if there was an allocation error
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Initialize digest operation for SHA256
    const EVP_MD *md = EVP_sha256();
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    unsigned char buffer[4096];
    size_t bytesRead;

    // Read the file in a loop and update the hash
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            ERR_print_errors_fp(stderr);
            exit(1);
        }
    }
    // Check to see if there was an error reading the file
    if (ferror(file)) {
        perror("Error reading file");
        fclose(file);
        EVP_MD_CTX_free(mdctx); // Free the digest context
        return 0;
    }

    //Finalize hash
    unsigned int hashLength;
    if (EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    fclose(file);
    EVP_MD_CTX_free(mdctx); // Free the digest context
    return 1;
}

//Compare two hashes
int compareHashes(const unsigned char *hash1, const unsigned char *hash2, size_t length) {
    //compare bytes of the two hashes
    return memcmp(hash1, hash2, length) == 0;
}

// Make sure 2 arguments are provided with program call
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s file1 file2\n", argv[0]);
        return EXIT_FAILURE;
    }

    unsigned char hash1[HASH_LENGTH];
    unsigned char hash2[HASH_LENGTH];

    // Compute file 1 hash and check for hashing error
    if (!calcSha256(argv[1], hash1)) {
        fprintf(stderr, "Failed to compute hash for file: %s\n", argv[1]);
        return EXIT_FAILURE;
    }
    // Compute file 2 hash and check for hashing error
    if (!calcSha256(argv[2], hash2)) {
        fprintf(stderr, "Failed to compute hash for file: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    if (compareHashes(hash1, hash2, HASH_LENGTH)) {
        printf("Files %s and %s are identical\n", argv[1], argv[2]);
    }
    else {
        printf("Files %s and %s differ\n", argv[1], argv[2]);
    }

    return EXIT_SUCCESS;
}