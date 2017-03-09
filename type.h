#ifndef TYPE_H
#define TYPE_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * Magic bytes that begin all FTCP connections and metadata files.
 */
#define FTCP_MAGIC 0x50435446

/**
 * Maximum length of a file name, including the NUL terminator.
 */
#define MAX_FILE_NAME_LEN 4096

/**
 * Minimum size of a block, in bytes. Must be a power of 2.
 */
#define MIN_BLOCK_SIZE 4096

/**
 * Maximum number of blocks to split a file into.
 */
#define MAX_NUM_BLOCKS 10000

/**
 * File ID structure
 */
typedef struct {
    char bytes[16];
} file_id_t;

/**
 * SHA-3-256 digest structure
 */
typedef struct {
    char digest[32];
} sha256_t;

/**
 * File metadata structure
 */
typedef struct {
    /**
     * FTCP magic bytes.
     */
    uint32_t magic;

    /**
     * Unique identifier of the file.
     */
    file_id_t id;

    /**
     * Length of the filename, including NUL terminator.
     * Will always be <= MAX_FILE_NAME_LEN.
     */
    uint32_t file_name_len;

    /**
     * Name of the file, including NUL terminator.
     */
    char file_name[MAX_FILE_NAME_LEN];

    /**
     * Size of the file in bytes.
     */
    uint64_t file_size;

    /**
     * SHA-3-256 hash of the entire file.
     */
    sha256_t file_hash;

    /**
     * Size of an individual block. Must be a power of 2.
     */
    uint64_t block_size;

    /**
     * Number of blocks. Must be less than or equal to
     * MAX_NUM_BLOCKS.
     */
    uint64_t block_count;

    /**
     * SHA-3-256 hash of each block.
     */
    sha256_t block_hashes[MAX_NUM_BLOCKS];
} file_meta_t;

#endif
