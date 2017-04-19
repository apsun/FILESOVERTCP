#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define DEBUG 1

#if DEBUG

#define debugf(...)            \
do {                           \
    printe("[%s:%u] %s: ", __FILE__, __LINE__, __func__); \
    printe(__VA_ARGS__);       \
    printe("\n");              \
} while(0)

#define debuge(...)            \
do {                           \
    printe("[%s:%u] %s: ", __FILE__, __LINE__, __func__); \
    printe(__VA_ARGS__);       \
    printe(": ");              \
    perror("");                \
} while (0)

#else

#define debugf(...) (void)0
#define debuge(...) (void)0

#endif

/**
 * Prints various colors
 */
void print_normal();
void print_red();
void print_green();
void print_yellow();
void print_blue();
void print_magneta();
void print_cyan();
void print_white();

/**
 * Prints the formatted message to stderr.
 */
void
printe(const char *fmt, ...);

/**
 * Similar to strncpy. Returns true iff all chars (including
 * the NUL terminator) were copied to dest. If the copy
 * succeeded, length is set to the value of the string
 * (not including the NUL terminator).
 */
bool
copy_string(char *dest, const char *src, size_t *length);

/**
 * Returns whether the string starts with the specified prefix.
 */
bool
starts_with(const char *str, const char *prefix);

/**
 * snprintf() wrapper that returns true on success.
 */
bool
format_string(char *dest, size_t size, const char *fmt, ...);

/**
 * Removes leading and trailing spaces/newlines.
 * Returns a pointer to the new start of the string.
 */
char *
trim_string(char *str);

/**
 * Gets the name (including file extension) of a file from
 * its full path. Returns true if the name fits in the output
 * buffer (and sets length to its length).
 */
bool
get_file_name(char *out_name, const char *path, size_t *length);

/**
 * Returns true if the file has the specified file extension.
 * The extension should begin with a '.'
 */
bool
has_file_extension(const char *file_name, const char *extension);

/**
 * Converts the specified IP address from integer to string form.
 * Returns the buffer that is passed in.
 */
char *
ipv4_itoa(uint32_t ip, char buf[16]);

/**
 * Converts the specified IP address from string to integer form.
 */
bool
ipv4_atoi(const char *ip, uint32_t *out_ip);

#endif
