#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>

/**
 * Starts the main client thread.
 */
int
client_run(void);

/**
 * TODO write something here
 */
static void *
client_thread(void *arg);

#endif
