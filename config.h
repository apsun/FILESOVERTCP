#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

/**
 * Loads the configuration from the specified
 * configuration file. If config_path is NULL,
 * default values are used.
 */
void
load_config(const char *config_path);

/**
 * Gets the directory in which FTCP internal state
 * files are stored.
 */
const char *
get_state_dir(void);

/**
 * Gets the directory in which downloaded files
 * are stored.
 */
const char *
get_download_dir(void);

/**
 * Gets the port that the FTCP server will listen on.
 */
uint16_t
get_server_port(void);

#endif
