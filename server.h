#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>

/**
 * Runs the main server loop, listening  on the specified port.
 */
int
server_loop(uint16_t port);

#endif
