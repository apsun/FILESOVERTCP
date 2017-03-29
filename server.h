#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <stdbool.h>

/**
 * Starts the main server thread, listening on the specified port.
 */
bool
server_run(uint16_t port);

#endif
