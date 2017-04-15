#define _GNU_SOURCE
#include "config.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

static const char *state_dir;
static const char *download_dir;
static uint16_t server_port;

void
load_config(const char *config_path)
{
    /* Default values */
    state_dir = "state";
    download_dir = "download";
    server_port = 8888;

    FILE *f = fopen(config_path, "r");
    if (f == NULL) {
        debuge("Failed to open config file");
        return;
    }

    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, f) != -1) {
        char *trimmed_line = trim_string(line);

        /* Ignore comment lines */
        if (trimmed_line[0] == '#') {
            continue;
        }

        /* TODO: This is the worst parsing code I've written in my life.
         * Add error checking and probably fix some security bugs.
         * Free allocated strings upon program exit.
         * Handle spaces in config around = properly
         */

        if (starts_with(trimmed_line, "state_dir=")) {
            state_dir = strdup(&trimmed_line[strlen("state_dir=")]);
        }

        if (starts_with(trimmed_line, "download_dir=")) {
            download_dir = strdup(&trimmed_line[strlen("download_dir=")]);
        }

        if (starts_with(trimmed_line, "server_port=")) {
            int tmp = atoi(&trimmed_line[strlen("server_port=")]);
            if (tmp == 0) {
                debugf("Invalid port #");
            } else {
                server_port = (uint16_t)tmp;
            }
        }
    }

    debugf("State dir: %s", state_dir);
    debugf("Download dir: %s", download_dir);
    debugf("Server port: %d", server_port);

    free(line);
    fclose(f);
}

const char *
get_state_dir(void)
{
    return state_dir;
}

const char *
get_download_dir(void)
{
    return download_dir;
}

uint16_t
get_server_port(void)
{
    return server_port;
}
