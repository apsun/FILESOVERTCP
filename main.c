#include "server.h"
#include "util.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

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
        return server_loop(8888);
    } else if (strcmp(mode, "client") == 0) {
        return 1; /* TODO */
    } else {
        return usage(argv[0]);
    }
}
