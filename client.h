#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>
#include <stdbool.h>

/**
 * Starts the main client thread.
 */
bool
client_run(const char *ip_addr, uint16_t port, uint16_t server_port, const char *file_name);

#endif
