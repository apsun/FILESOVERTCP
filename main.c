#include "server.h"
#include "client.h"
#include "util.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "type.h"
#include <pthread.h>
#include <dirent.h>
#include "block.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int
usage(const char *name) //this function is outdated.
{
    printe("usage: %s <mode>\n", name);
    printe("  mode -- \"client\" or \"server\"\n");
    return 1;
}

int
main(int argc, char **argv)
{
    const char *dirName = argv[1];
    add_files(dirName);

    server_run(8888);
    client_run(0x7f000001, 8888, "file.txt");
    while (1);
    return 0;
}
