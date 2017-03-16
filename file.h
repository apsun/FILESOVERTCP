#ifndef FILE_H
#define FILE_H

#include <stdbool.h>
#include <stdint.h>
#include "type.h"

/**
 * Sets the status of a block and flushes the changes
 * to disk. Returns true if the block file could be written.
 */
bool
set_block_status(file_state_t *file, uint32_t index, block_status_t bs);

/**
 * Adds all the files in file_path and sets all the blocks as downloaded
 * Returns false if it can not open the directory.
 */
bool
add_directory(const char *file_path);

/**
 * Adds a file given the meta.
 * Returns a pointer to a filestate object.
 */
file_state_t *
add_file(file_meta_t *meta);

/**
 * Creates a new local file and all its associated metadata files.
 */
file_state_t *
create_local_file(file_meta_t *meta);

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

#endif
