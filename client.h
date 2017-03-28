#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "type.h"

/**
 * Starts the main client thread.
 */
bool
client_run(const char *ip_addr, uint16_t port, uint16_t server_port, const char *file_name);

/**
 * Resumes the main client thread.
 */
bool
client_resume(peer_info_t peerinfo, uint16_t server_port, file_state_t * file);

#endif
