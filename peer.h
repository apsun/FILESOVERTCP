#ifndef PEER_H
#define PEER_H

#include <stdbool.h>
#include "type.h"

/**
 * Gets the peer list for a particular file. Returns the
 * number of peers in the list.
 */
uint32_t
get_peer_list(file_state_t *file, peer_info_t peer_list[MAX_NUM_PEERS]);

/**
 * Adds a new peer to the peer list for the given file.
 */
bool
peer_add(file_state_t *file, peer_info_t peer);

/**
 * Removes the given peer from the peer list for the given file.
 */
bool
peer_remove(file_state_t *file, peer_info_t peer);

#endif
