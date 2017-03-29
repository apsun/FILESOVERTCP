#define _XOPEN_SOURCE 500
#include "io.h"
#include "util.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/time.h>

bool
send_all(int sockfd, const void *buf, size_t count)
{
    const char *bufc = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t num = send(sockfd, bufc + total, count - total, MSG_NOSIGNAL);
        if (num < 0) {
            debuge("send_all() failed");
            return false;
        }
        total += num;
    }
    return true;
}

bool
recv_all(int sockfd, void *buf, size_t count)
{
    char *bufc = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t num = recv(sockfd, bufc + total, count - total, MSG_WAITALL);
        if (num < 0) {
            debuge("recv_all() failed");
            return false;
        } else if (num == 0) {
            debugf("EOF reached before count");
            return false;
        }
        total += num;
    }
    return true;
}

bool
write_all(int fd, const void *buf, size_t count)
{
    const char *bufc = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t num = write(fd, bufc + total, count - total);
        if (num < 0) {
            debuge("write_all() failed");
            return false;
        }
        total += num;
    }
    return true;
}

bool
read_all(int fd, void *buf, size_t count)
{
    char *bufc = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t num = read(fd, bufc + total, count - total);
        if (num < 0) {
            debuge("read_all() failed");
            return false;
        } else if (num == 0) {
            debugf("EOF reached before count");
            return false;
        }
        total += num;
    }
    return true;
}

bool
write_block(int fd, const void *buf, size_t count, off_t file_offset)
{
    const char *bufc = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t num = pwrite(fd, bufc + total, count - total, file_offset + total);
        if (num < 0) {
            debuge("write_block() failed");
            return false;
        }
        total += num;
    }
    return true;
}

bool
read_block(int fd, void *buf, size_t count, off_t file_offset)
{
    char *bufc = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t num = pread(fd, bufc + total, count - total, file_offset + total);
        if (num < 0) {
            debuge("read_block() failed");
            return false;
        } else if (num == 0) {
            debugf("Reached EOF, padding with NUL bytes");
            memset(bufc + total, 0, count - total);
            return true;
        }
        total += num;
    }
    return true;
}

bool
read_string(read_fn fn, int fd, char *buf, uint32_t *len)
{
    /* Read length */
    uint32_t str_len;
    if (!fn(fd, &str_len, sizeof(str_len))) {
        return false;
    }

    /* Validate length */
    if (str_len == 0 || str_len > *len) {
        return false;
    }

    /* Read actual string */
    if (!fn(fd, buf, str_len)) {
        return false;
    }

    /* Ensure we have a NUL terminator */
    if (buf[str_len - 1] != '\0') {
        return false;
    }

    /* Check for embedded NUL characters */
    if (strlen(buf) != str_len - 1) {
        return false;
    }

    *len = str_len;
    return true;
}

bool
write_string(write_fn fn, int fd, const char *buf, uint32_t len)
{
    /* Write length */
    if (!fn(fd, &len, sizeof(len))) {
        return false;
    }

    /* Write string */
    if (!fn(fd, buf, len)) {
        return false;
    }

    return true;
}

bool
read_file_id(read_fn fn, int fd, file_id_t *id)
{
    for (int i = 0; i < 16; ++i) {
        if (!fn(fd, &id->bytes[i], 1)) {
            return false;
        }
    }
    return true;
}

bool
write_file_id(write_fn fn, int fd, const file_id_t *id)
{
    for (int i = 0; i < 16; ++i) {
        if (!fn(fd, &id->bytes[i], 1)) {
            return false;
        }
    }
    return true;
}

bool
read_sha256(read_fn fn, int fd, sha256_t *hash)
{
    for (int i = 0; i < 32; ++i) {
        if (!fn(fd, &hash->digest[i], 1)) {
            return false;
        }
    }
    return true;
}

bool
write_sha256(write_fn fn, int fd, const sha256_t *hash)
{
    for (int i = 0; i < 32; ++i) {
        if (!fn(fd, &hash->digest[i], 1)) {
            return false;
        }
    }
    return true;
}

bool
read_magic(read_fn fn, int fd)
{
    uint32_t magic;
    if (!fn(fd, &magic, sizeof(magic))) {
        return false;
    }

    if (magic != FTCP_MAGIC) {
        return false;
    }

    return true;
}

bool
write_magic(write_fn fn, int fd)
{
    uint32_t magic = FTCP_MAGIC;
    if (!fn(fd, &magic, sizeof(magic))) {
        return false;
    }

    return true;
}

bool
read_peer(read_fn fn, int fd, peer_info_t *peer)
{
    if (!fn(fd, &peer->ip_addr, sizeof(peer->ip_addr))) {
        return false;
    }

    if (!fn(fd, &peer->port, sizeof(peer->port))) {
        return false;
    }

    return true;
}

bool
write_peer(write_fn fn, int fd, const peer_info_t *peer)
{
    if (!fn(fd, &peer->ip_addr, sizeof(peer->ip_addr))) {
        return false;
    }

    if (!fn(fd, &peer->port, sizeof(peer->port))) {
        return false;
    }

    return true;
}

bool
read_block_status(read_fn fn, int fd, block_status_t *bs)
{
    uint32_t bs_int;
    if (!fn(fd, &bs_int, sizeof(bs_int))) {
        return false;
    }

    *bs = (block_status_t)bs_int;
    return true;
}

bool
write_block_status(write_fn fn, int fd, const block_status_t *bs)
{
    uint32_t bs_int = (uint32_t)*bs;
    if (!fn(fd, &bs_int, sizeof(bs_int))) {
        return false;
    }

    return true;
}

bool
read_file_meta(read_fn fn, int fd, file_meta_t *meta)
{
    if (!read_file_id(fn, fd, &meta->id)) {
        return false;
    }

    meta->file_name_len = MAX_FILE_NAME_LEN;
    if (!read_string(fn, fd, meta->file_name, &meta->file_name_len)) {
        return false;
    }

    if (!fn(fd, &meta->file_size, sizeof(meta->file_size))) {
        return false;
    }

    if (!fn(fd, &meta->file_hash, sizeof(meta->file_hash))) {
        return false;
    }

    if (!fn(fd, &meta->block_size, sizeof(meta->block_size))) {
        return false;
    }

    if (!fn(fd, &meta->block_count, sizeof(meta->block_count))) {
        return false;
    }

    if (meta->block_count > MAX_NUM_BLOCKS) {
        return false;
    }

    for (uint32_t i = 0; i < meta->block_count; ++i) {
        if (!read_sha256(fn, fd, &meta->block_hashes[i])) {
            return false;
        }
    }

    return true;
}

bool
write_file_meta(write_fn fn, int fd, const file_meta_t *meta)
{
    if (!write_file_id(fn, fd, &meta->id)) {
        return false;
    }

    if (!write_string(fn, fd, meta->file_name, meta->file_name_len)) {
        return false;
    }

    if (!fn(fd, &meta->file_size, sizeof(meta->file_size))) {
        return false;
    }

    if (!fn(fd, &meta->file_hash, sizeof(meta->file_hash))) {
        return false;
    }

    if (!fn(fd, &meta->block_size, sizeof(meta->block_size))) {
        return false;
    }

    if (!fn(fd, &meta->block_count, sizeof(meta->block_count))) {
        return false;
    }

    for (uint32_t i = 0; i < meta->block_count; ++i) {
        if (!write_sha256(fn, fd, &meta->block_hashes[i])) {
            return false;
        }
    }

    return true;
}

bool
read_file_state(read_fn fn, int fd, file_state_t *state)
{
    if (!read_file_meta(fn, fd, &state->meta)) {
        return false;
    }

    state->file_path_len = MAX_PATH_LEN;
    if (!read_string(fn, fd, state->file_path, &state->file_path_len)) {
        return false;
    }

    state->state_path_len = MAX_PATH_LEN;
    if (!read_string(fn, fd, state->state_path, &state->state_path_len)) {
        return false;
    }

    for (uint32_t i = 0; i < state->meta.block_count; ++i) {
        if (!read_block_status(fn, fd, &state->block_status[i])) {
            return false;
        }
    }

    if (!fn(fd, &state->num_peers, sizeof(state->num_peers))) {
        return false;
    }

    if (state->num_peers > MAX_NUM_PEERS) {
        return false;
    }

    for (uint32_t i = 0; i < state->num_peers; ++i) {
        if (!read_peer(fn, fd, &state->peer_list[i])) {
            return false;
        }
    }

    return true;
}

bool
write_file_state(write_fn fn, int fd, const file_state_t *state)
{
    if (!write_file_meta(fn, fd, &state->meta)) {
        return false;
    }

    if (!write_string(fn, fd, state->file_path, state->file_path_len)) {
        return false;
    }

    if (!write_string(fn, fd, state->state_path, state->state_path_len)) {
        return false;
    }

    for (uint32_t i = 0; i < state->meta.block_count; ++i) {
        if (!write_block_status(fn, fd, &state->block_status[i])) {
            return false;
        }
    }

    if (!fn(fd, &state->num_peers, sizeof(state->num_peers))){
        return false;
    }

    for (uint32_t i = 0; i < state->num_peers; ++i) {
        if (!write_peer(fn, fd, &state->peer_list[i])) {
            return false;
        }
    }

    return true;
}
