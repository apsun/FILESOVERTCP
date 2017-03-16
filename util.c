// for pwrite and pread
#define _XOPEN_SOURCE 500

#include "util.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

void
printe(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
}

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
copy_string(char *dest, const char *src, size_t *length)
{
    size_t n = *length;
    for (size_t i = 0; i < n; ++i) {
        if ((dest[i] = src[i]) == '\0') {
            *length = i;
            return true;
        }
    }
    return false;
}

bool
get_file_name(char *out_name, const char *path, size_t *length)
{
    char *s = strrchr(path, '/');
    if (s == NULL) {
        return copy_string(out_name, path, length);
    } else {
        return copy_string(out_name, s + 1, length);
    }
}

bool
has_file_extension(const char *file_name, const char *extension)
{
    const char *c = strrchr(file_name, '.');
    if (c != NULL) {
        return strcmp(c, extension) == 0;
    } else {
        return false;
    }
}
