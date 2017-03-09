#include "block.h"

uint64_t
block_calculate_size(uint64_t file_size)
{
    uint64_t block_size = MIN_BLOCK_SIZE;
    while (file_size / block_size > MAX_NUM_BLOCKS) {
        block_size *= 2;
    }
    return block_size;
}
