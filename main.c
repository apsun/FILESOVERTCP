#include "server.h"
#include "client.h"
#include "util.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

//GLOBAL DECLARATIONS change to pointers.

/**
 * Array holding meta information for all files we have or are getting.
 */
file_meta_t filelist[MAX_NUM_FILES];
/**
 * Array holding meta information of blocks for all files we have or are getting.
 */
char blocklist[MAX_FILES][MAX_NUM_BLOCKS];
/**
 * Represents how many files we have or are getting.
 */
int files = 0;
/**
 * Array of fd for files we have or are getting.
 */
int fdList[MAX_FILES];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;


static int
usage(const char *name)
{
    printe("usage: %s <mode>\n", name);
    printe("  mode -- \"client\" or \"server\"\n");
    return 1;
}

int
main(int argc, char **argv)
{
    if (argc != 2) {
        return usage(argv[0]);
    }

    const char *mode = argv[1];
    if (strcmp(mode, "server") == 0) {
        return server_run(8888);
    } else if (strcmp(mode, "client") == 0) {
        return client_run();
    } else {
        return usage(argv[0]);
    }
}
