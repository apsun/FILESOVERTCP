#ifndef FILE_H
#define FILE_H

#include <stdbool.h>
#include <stdint.h>
#include "type.h"

/**
 * Adds a remote file for downloading.
 */
bool
add_remote_file(const file_meta_t *meta, file_state_t **file);

/**
 * Adds a local file for uploading.
 */
bool
add_local_file(const char *file_path, file_state_t **file);

/**
 * Sets the status of a block.
 */
void
set_block_status(file_state_t *file, uint32_t index, block_status_t bs);


/**
 * Removes downloading blocks from the block list.
 */
void
remove_downloading_blocks(file_state_t *file);

/**
 * Initializes the file storage.
 */
bool
initialize(void);

/**
 * Flushes all dynamic state to disk.
 */
bool
flush(void);

/**
 * Closes all files. Call this at application shutdown.
 */
bool
finalize(void);

/**
 * Gets a file by name. Returns true and writes out_file
 * if the file exists, and returns false otherwise.
 */
bool
get_file_by_name(const char *file_name, file_state_t **out_file);

/**
 * Gets a file by its ID. Returns true and writes out_file
 * if the file exists, and returns false otherwise.
 */
bool
get_file_by_id(const file_id_t *id, file_state_t **out_file);


/**
 * Gets a file by its index. Returns true and writes out_file
 * if the file exists, and returns false otherwise.
 */
bool
get_file_by_index(int index, file_state_t **out_file);

/**
 * Returns the num of files
 */
int
get_num_files();

/**
 * Gets the block status list for a particular file. Returns
 * the number of blocks in the list.
 */
uint32_t
get_block_status_list(file_state_t *file, block_status_t block_status[MAX_NUM_BLOCKS]);

/**
 * Gets the data of a block. The size of the buffer pointed to
 * by block_data must be at least as large as the block size
 * of the file.
 */
bool
get_block_data(file_state_t *file, uint32_t block_index, uint8_t *block_data);

/**
 * Returns whether we have successfully downloaded all blocks
 * in the file.
 */
bool
have_all_blocks(file_state_t *file);

/**
 * Gets the index of a block that is not already downloaded
 * and has the corresponding bit set to 1 in the block bitmap.
 * Returns false if there is no such block. The returned block,
 * if any, has its status atomically set to BS_DOWNLOADING.
 */
bool
find_needed_block(file_state_t *file, uint8_t *block_bitmap, uint32_t *block_index);

/**
 * Validates a downloaded block. Returns true iff the block data
 * matches its expected hash.
 */
bool
check_block(file_state_t *file, uint32_t block_index, uint8_t *block_data);

/**
 * Generates an array containtng all of the blockindexes of a file in a random order
 * Returns a malloced array (NULL if malloc fails).
 */
uint32_t *
generate_random_block_order(file_state_t *file);

#endif
