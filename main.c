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
#include <stdarg.h>

static int
usage(const char *name)
{
    printe("usage: %s <options>\n", name);
    printe(" -c <path> -- config file path");
    return 1;
}

int
main(int argc, char **argv)
{
    if (argc != 1) {
        return usage(argv[0]);
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while (true) {
        printe("FTCP> ");
        if ((read = getline(&line, &len, stdin)) < 0) {
            break;
        }

        char *cmd = trim_string(line);
        if (starts_with(cmd, "download ")) {

        } else if (starts_with(cmd, "upload ")) {

        } else if (starts_with(cmd, "status ")) {

        } else if (strcmp(cmd, "exit") == 0) {
            break;
        } else {
            printe("Unknown command! Valid commands are:\n");
            printe("> download 127.0.0.1[:8888] file.txt\n");
            printe("> upload path/to/file.txt\n");
            printe("> status file.txt\n");
        }
    }

    printe("Bye!\n");
    free(line);
    return 0;
}
