#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

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


/**
 * Prints the formatted message to stderr.
 */
void
printe(const char *fmt, ...);

/**
 * Like write_all(), but doesn't cause a SIGPIPE when
 * writing to broken pipes. Only works on socket files.
 */
bool
send_all(int sockfd, const void *buf, size_t count);

/**
 * Like read_all(), but only works on socket files.
 */
bool
recv_all(int sockfd, void *buf, size_t count);

/**
 * Writes count bytes from buf to the specified file.
 * Only returns once count bytes have been written, or
 * a write fails.
 */
bool
write_all(int fd, const void *buf, size_t count);

/**
 * Reads count bytes from the specified file into buf.
 * Only returns once count bytes have been read, or
 * a read fails.
 */
bool
read_all(int fd, void *buf, size_t count);

/**
 * Writes count bytes from buf to the specified file
 * at the given file offset. Returns true if all bytes
 * could be written, false otherwise.
 */
bool
write_block(int fd, const void *buf, size_t count, off_t file_offset);

/**
 * Reads count bytes from the specified file into buf
 * at the given file offset. Returns true if all bytes
 * could be read, false otherwise. If EOF is reached before
 * count bytes are read, the remainder of buf is filled
 * with 0s and true is returned.
 */
bool
read_block(int fd, void *buf, size_t count, off_t file_offset);

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
