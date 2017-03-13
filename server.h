#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>

/**
 * Starts the main server thread, listening on the specified port.
 */
int
server_run(uint16_t port);

/**
 * TODO write something here
 */
void *
server_thread(void *arg);

#endif
