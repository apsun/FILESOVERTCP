#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>

/**
 * Starts the main client thread.
 */
void
client_run(uint32_t ip_addr, uint16_t port, const char *file_name);



#endif
