#define _GNU_SOURCE
#include "server.h"
#include "client.h"
#include "util.h"
#include "type.h"
#include "file.h"
#include "config.h"
#include "peer.h"
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

    load_config(NULL);
    initialize();
    server_run(8888);
    int files = get_num_files();
    for(int i = 0; i < files; i++)
    {
        file_state_t * filetemp;
        if(get_file_by_index(i, &filetemp))
        {
            remove_downloading_blocks(filetemp);
            peer_info_t peer_list[MAX_NUM_PEERS];
            uint32_t numpeers = get_peer_list(filetemp, peer_list);
            for(uint32_t j = 0; j < numpeers; j++)
            {
                client_resume(peer_list[j] , 8889, filetemp);
            }
        }
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
            char *fname = cmd + strlen("download ");
            fname = trim_string(fname);
            client_start("127.0.0.1", 8888, 8889, fname);
            flush();
        } else if (starts_with(cmd, "upload ")) {
            char *path = cmd + strlen("upload ");
            path = trim_string(path);
            file_state_t *f;
            add_local_file(path, &f);
            flush();
        } else if (starts_with(cmd, "status ")) {
            char *fname = cmd + strlen("status ");
            fname = trim_string(fname);
            file_state_t *f;
            if (!get_file_by_name(fname, &f)) {
                printe("Unknown file\n");
            } else {
                printe("OK!\n");
                printe("File name: %s\n", f->meta.file_name);
                printe("File size: %ld\n", f->meta.file_size);
                printe("Number of peers: %d\n", f->num_peers);
            }
        } else if (strcmp(cmd, "exit") == 0) {
            break;
        } else {
            printe("Unknown command! Valid commands are:\n");
            printe("> download file.txt\n");
            printe("> upload path/to/file.txt\n");
            printe("> status file.txt\n");
            printe("> exit\n");
        }
    }

    flush();
    finalize();
    printe("Bye!\n");
    free(line);
    return 0;
}
