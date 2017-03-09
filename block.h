#ifndef BLOCK_H
#define BLOCK_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Minimum size of a block, in bytes. Must be a power of 2.
 */
#define MIN_BLOCK_SIZE 4096

/**
 * Maximum number of blocks to split a file into.
 */
#define MAX_NUM_BLOCKS 10000

/**
 * Calculates the optimal size of a block (in bytes) used
 * to transfer a file of the specified size.
 */
uint64_t
block_calculate_size(uint64_t file_size);

#endif
