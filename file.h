#include <stdbool.h>
#include <stdint.h>
#include "type.h"

bool
get_file_by_name(const char *file_name, file_state_t **out_file);

bool
file_id_equals(const file_id_t *a, const file_id_t *b);

bool
get_file_by_id(const file_id_t *id, file_state_t **out_file);

uint32_t
get_peer_list(file_state_t *file, peer_info_t peer_list[MAX_NUM_PEERS]);

uint32_t
get_block_status_list(file_state_t *file, block_status_t block_status[MAX_NUM_BLOCKS]);

bool
get_block_data(file_state_t *file, uint32_t block_index, uint8_t *block_data);

