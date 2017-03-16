#include "server.h"
#include "client.h"
#include "util.h"
#include "type.h"
#include "file.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int
usage(const char *name)
{
    printe("usage: %s <mode> <name>\n", name);
    printe("  mode -- \"client\" or \"server\"\n");
    printe("  name -- directory if server mode, file name if client mode\n");
    return 1;
}

int
main(int argc, char **argv)
{
    if (argc != 3) {
        return usage(argv[0]);
    }

    const char *mode = argv[1];
    const char *name = argv[2];

    if (strcmp(mode, "server") == 0) {
        add_directory(name);
        server_run(8888);
    } else if (strcmp(mode, "client") == 0) {
        client_run(0x7f000001, 8888, 8888, name);
    }
    
    while (1);
    return 0;
}
