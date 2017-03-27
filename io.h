#ifndef IO_H
#define IO_H

#include "type.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

typedef bool (*write_fn)(int fd, const void *buf, size_t count);
typedef bool (*read_fn)(int fd, void *buf, size_t count);

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
 * Reads a string using the specified read function from the
 * given file descriptor. The first 4 bytes must equal the
 * length of the string INCLUDING THE NUL TERMINATOR. When calling
 * the function, *len must equal the size of the buffer, and
 * upon success, it will equal the length of the actual read string.
 */
bool
read_string(read_fn fn, int fd, char *buf, uint32_t *len);

/**
 * Writes a string using the specified write function. Same
 * rules as read_string().
 */
bool
write_string(write_fn fn, int fd, const char *buf, uint32_t len);

bool
read_file_id(read_fn fn, int fd, file_id_t *id);

bool
write_file_id(write_fn fn, int fd, const file_id_t *id);

bool
read_sha256(read_fn fn, int fd, sha256_t *hash);

bool
write_sha256(write_fn fn, int fd, const sha256_t *hash);

bool
read_magic(read_fn fn, int fd);

bool
write_magic(write_fn fn, int fd);

bool
read_peer(read_fn fn, int fd, peer_info_t *peer);

bool
write_peer(write_fn fn, int fd, const peer_info_t *peer);

bool
read_block_status(read_fn fn, int fd, block_status_t *bs);

bool
write_block_status(write_fn fn, int fd, const block_status_t *bs);

bool
read_file_meta(read_fn fn, int fd, file_meta_t *meta);

bool
write_file_meta(write_fn fn, int fd, const file_meta_t *meta);

bool
read_file_meta(read_fn fn, int fd, file_meta_t *meta);

bool
write_file_meta(write_fn fn, int fd, const file_meta_t *meta);

bool
read_file_state(read_fn fn, int fd, file_state_t *state);

bool
write_file_state(write_fn fn, int fd, const file_state_t *state);

#endif
