#include "config.h"
#include <stdint.h>

static const char *state_dir;
static const char *download_dir;
static uint16_t server_port;

void
load_config(const char *config_path)
{
    /* TODO */
    state_dir = "state";
    download_dir = "download";
    server_port = 8888;
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
