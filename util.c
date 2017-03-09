#include "util.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

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
write_all(int fd, const void *buf, size_t count)
{
    const char *bufc = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t num = write(fd, bufc + total, count - total);
        if (num < 0) {
            perror("Write failed");
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
        if (num <= 0) {
            perror("Read failed");
            return false;
        }
        total += num;
    }
    return true;
}

bool
write_block(int fd, const void *buf, size_t count, off_t file_offset)
{
    /* TODO */
    return false;
}

bool
read_block(int fd, void *buf, size_t count, off_t file_offset)
{
    /* TODO */
    return false;
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
