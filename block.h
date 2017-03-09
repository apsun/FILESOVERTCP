#ifndef BLOCK_H
#define BLOCK_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Calculates the optimal size of a block (in bytes) used
 * to transfer a file of the specified size.
 */
uint64_t
block_calculate_size(uint64_t file_size);

#endif
