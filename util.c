//for pwrite and pread
#define _XOPEN_SOURCE 500

#include "util.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>


extern pthread_mutex_t lock;
extern int files;
extern file_meta_t filelist[MAX_NUM_FILES];
extern int fdList[MAX_NUM_FILES];
extern char blocklist[MAX_NUM_FILES][MAX_NUM_BLOCKS];


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
            perror("Write failed");
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
            perror("Read failed");
            return false;
        } else if (num == 0) {
            printe("EOF reached before count\n");
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
        if (num < 0) {
            perror("Read failed");
            return false;
        } else if (num == 0) {
            printe("EOF reached before count\n");
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
        ssize_t num = pwrite(fd, bufc + total, count - total, file_offset);
        if (num < 0) {
            perror("Write failed");
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
        ssize_t num = pread(fd, bufc + total, count - total, file_offset);
        if (num < 0) {
            perror("Read failed");
            return false;
        } else if (num == 0) {
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
get_file_meta_by_filename(char * filename, file_meta_t *file_meta)
{
    pthread_mutex_lock(&lock);
    for(int i = 0; i < files; i++)
    {
        file_meta_t temp = filelist[i];
        if(strcmp(temp.file_name, filename) == 0)
        {
            pthread_mutex_unlock(&lock);
            *file_meta = temp;
            return true;
        }
    }
    pthread_mutex_unlock(&lock);
    return false;
}

bool
file_id_compare(file_id_t file_id1, file_id_t file_id2)
{
    for(int i = 0; i < 16; i++)
    {
        if(file_id1.bytes[i] != file_id2.bytes[i])
        {
            return false;
        }
    }
    return true;
}

bool
get_file_meta_by_file_id(file_id_t file_id, int * index, int * fd, file_meta_t *file_meta)
{
    pthread_mutex_lock(&lock);
    for(int i = 0; i < files; i++)
    {
        file_meta_t temp = filelist[i];
        if(file_id_compare(file_id, temp.id)) //can probably do this with memcmp but this should be more safe.
        {
            *fd = fdList[i];
            pthread_mutex_unlock(&lock);
            *index = i;
            *file_meta = temp;
            return true;
        }
    }
    pthread_mutex_unlock(&lock);
    return false;
}

bool
have_block(int file_index, uint64_t block_index)
{
    pthread_mutex_lock(&lock);
    if(blocklist[file_index][block_index] == 2)
    {
        pthread_mutex_unlock(&lock);
        return false;
    }
    pthread_mutex_unlock(&lock);
    return true;
}
