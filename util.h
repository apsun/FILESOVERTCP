#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stdbool.h>

/**
 * Prints the formatted message to stderr.
 */
void
printe(const char *fmt, ...);

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
write_block(int fd, const void *buf, size_t count, off_t file_offset)

/**
 * Reads count bytes from the specified file into buf
 * at the given file offset. Returns true if all bytes
 * could be read, false otherwise. If EOF is reached before
 * count bytes are read, the remainder of buf is filled
 * with 0s and true is returned.
 */
bool
read_block(int fd, void *buf, size_t count, off_t file_offset)

/**
 * Similar to strncpy. Returns true iff all chars (including
 * the NUL terminator) were copied to dest. If the copy
 * succeeded, length is set to the value of the string
 * (not including the NUL terminator).
 */
bool
copy_string(char *dest, const char *src, size_t *length);

/**
 * Gets the name (including file extension) of a file from
 * its full path. Returns true if the name fits in the output
 * buffer (and sets length to its length). 
 */
bool
get_file_name(char *out_name, const char *path, size_t *length);

#endif