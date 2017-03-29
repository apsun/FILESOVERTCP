// for pwrite and pread
#define _XOPEN_SOURCE 500
#include "util.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
starts_with(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

bool
format_string(char *dest, size_t size, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    size_t num = vsnprintf(dest, size, fmt, args);
    va_end(args);
    fflush(stderr);
    return num < size;
}

char *
trim_string(char *str)
{
    while (*str && (*str == ' ' || *str == '\n')) {
        str++;
    }

    ssize_t end = (ssize_t)strlen(str) - 1;
    while (end >= 0 && (str[end] == ' ' || str[end] == '\n')) {
        str[end--] = '\0';
    }

    return str;
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

char *
ipv4_itoa(uint32_t ip, char buf[16])
{
    struct in_addr addr;
    addr.s_addr =  htonl(ip);
    char *str = inet_ntoa(addr);
    strncpy(buf, str, 16);
    return buf;
}

bool
ipv4_atoi(const char *ip, uint32_t *out_ip)
{
    in_addr_t ip_n = inet_addr(ip);
    if (ip_n == INADDR_NONE) {
        return false;
    }
    *out_ip = ntohl((uint32_t)ip_n);
    return true;
}
