#include <stdbool.h>
#include <stdint.h>
#include "type.h"


/**
 * Marks the block as what it wants
 */
bool
mark_block(filestate_t * file, uint32_t index, block_status_t bs);
/**
 * Checks if a peer is new
 * If it is adds it to the peerlist and returns true.
 */
bool
add_new_peer(filestate_t * file, peer_info_t peer);

/**
 * Adds all the files in file_path and sets all the blocks as downloaded
 * Returns false if it can not open the directory.
 */
bool
add_files(const char *file_path);

/**
 * Adds a file given the meta.
 * Returns a pointer to a filestate object.
 */
file_state_t *
add_file(file_meta_t meta);


/**
 * Gets a file by name. Returns true and writes out_file
 * if the file exists, and returns false otherwise.
 */
bool
get_file_by_name(const char *file_name, file_state_t **out_file);

/**
 * Returns true iff the ID represented by a equals the ID
 * represented by b.
 */
bool
file_id_equals(const file_id_t *a, const file_id_t *b);

/**
 * Gets a file by its ID. Returns true and writes out_file
 * if the file exists, and returns false otherwise.
 */
bool
get_file_by_id(const file_id_t *id, file_state_t **out_file);

/**
 * Gets the peer list for a particular file. Returns the
 * number of peers in the list.
 */
uint32_t
get_peer_list(file_state_t *file, peer_info_t peer_list[MAX_NUM_PEERS]);

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

