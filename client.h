#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>

/**
 * Starts the main client thread.
 */
void *
client_run(void* args);

void *
client_connect(void * args);


#endif
