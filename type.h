#ifndef TYPE_H
#define TYPE_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

/**
 * Magic bytes that begin all FTCP connections and metadata files.
 */
#define FTCP_MAGIC 0x50435446

/**
 * Maximum length of a file name, including the NUL terminator.
 */
#define MAX_FILE_NAME_LEN 256

/**
 * Minimum size of a block, in bytes. Must be a power of 2.
 */
#define MIN_BLOCK_SIZE 4096

/**
 * Maximum number of blocks to split a file into.
 */
#define MAX_NUM_BLOCKS 1000

/**
 * Maximum number of files supported at once.
 */
#define MAX_NUM_FILES 100

/**
 * Maximum number of peers per file (ONLY TEMPORARY)
 */
#define MAX_NUM_PEERS 100

/**
 * Extension for metadata files.
 */
#define META_FILE_EXT ".ftcp"

/**
 * Extension for block info files.
 */
#define BLOCK_FILE_EXT ".fblk"

/**
 * File ID structure
 */
typedef struct {
    uint8_t bytes[16];
} file_id_t;

/**
 * SHA-3-256 digest structure
 */
typedef struct {
    uint8_t digest[32];
} sha256_t;

/**
 * Peer info structure
 */
typedef struct {
    uint32_t ip_addr;
    uint16_t port;
} peer_info_t;

/**
 * Possible state of each block
 */
typedef enum {
    BS_DONT_HAVE,
    BS_DOWNLOADING,
    BS_HAVE,
} block_status_t;

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
    uint32_t block_count;

    /**
     * SHA-3-256 hash of each block.
     */
    sha256_t block_hashes[MAX_NUM_BLOCKS];
} file_meta_t;

/**
 * File state (mutable)
 */
typedef struct {
    /* File info */
    file_meta_t meta;

    /* Lock for this file struct */
    pthread_mutex_t lock;

    /* Block info */
    block_status_t block_status[MAX_NUM_BLOCKS];

    /* Peer list for this file */
    uint32_t num_peers;
    peer_info_t peer_list[MAX_NUM_PEERS];

    /* File descriptor for the actual file */
    int file_fd;

    /* File descriptor for the block status file */
    int block_info_fd;
} file_state_t;

#endif
