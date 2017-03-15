#include "file.h"
#include "util.h"
#include "type.h"
#include "cmd.h"
#include "block.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

static int num_files;
static file_state_t files[MAX_NUM_FILES];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

bool
add_files(const char *file_path)
{
    const char *dirName = file_path;
    struct dirent *entry;
    DIR *dp;

    dp = opendir(dirName);
    if (dp == NULL) {
        printe("Can not open directory");
        return false;
    }
    pthread_mutex_lock(&lock);
    while((entry = readdir(dp)))
    {
        char pathname[4096]; //the maximum path length on linux
        sprintf( pathname, "%s/%s", dirName, entry->d_name );
        files[num_files].file_fd = open( pathname, O_RDONLY ); //should only need to be read to
        struct stat buf;
        fstat(files[num_files], &buf);
        files[num_files].meta.magic = FTCP_MAGIC;
        files[num_files].meta.file_name_len = strlen(entry->d_name) + 1;
        files[num_files].meta.file_size = buf.st_size;
        files[num_files].meta.block_size = block_calculate_size(filelist[files].file_size);
        files[num_files].meta.block_count = (files[num_files].meta.file_size % files[num_files].meta.block_size) ? (files[num_files].file_size / files[num_files].block_size) + 1 : (files[num_files].file_size / files[num_files].block_size);
        //filelist[files].file_hash = ?
        randomGUID(&files[num_files].meta.id); 
        for(size_t i = 0; i < filelist[files].file_name_len; i++)
        {
            files[num_files].meta.file_name[i] = entry->d_name[i]; // gets the file name and sets it.
        }
        for(size_t i = 0; i < filelist[files].block_count; i++)
        {
            //filelist[files].block_hashes[i] = ?; dont know how to hash.
            files[num_files].block_status = 2; //we have everthing
        }
        files[num_files].lock = PTHREAD_MUTEX_INITIALIZER;
        num_files++;
    }
    pthread_mutex_unlock(&lock);
    return true;
}
file_state_t *
add_file(file_meta_t * meta)
{
    pthread_mutex_lock(&lock);
    files[num_files].file_fd = open( meta->file_name, O_CREAT | O_RDWR );
    files[num_files].meta = *meta;
    files[num_files].lock = PTHREAD_MUTEX_INITIALIZER;
    num_files++;
    pthread_mutex_unlock(&lock);
    return &files[num_files - 1];
}

bool
get_file_by_name(const char *file_name, file_state_t **out_file)
{
    pthread_mutex_lock(&lock);
    for (int i = 0; i < num_files; ++i) {
        if (strcmp(file_name, files[i].meta.file_name)) {
            *out_file = &files[i];
            pthread_mutex_unlock(&lock);
            return true;
        }
    }
    pthread_mutex_unlock(&lock);
    return false;
}

bool
file_id_equals(const file_id_t *a, const file_id_t *b)
{
    return memcmp(a, b, sizeof(file_id_t)) == 0;
}

bool
get_file_by_id(const file_id_t *id, file_state_t **out_file)
{
    pthread_mutex_lock(&lock);
    for (int i = 0; i < num_files; ++i) {
        if (file_id_equals(id, &files[i].meta.id)) {
            *out_file = &files[i];
            pthread_mutex_unlock(&lock);
            return true;
        }
    }
    pthread_mutex_unlock(&lock);
    return false;
}

uint32_t
get_peer_list(file_state_t *file, peer_info_t peer_list[MAX_NUM_PEERS])
{
    pthread_mutex_lock(&file->lock);
    uint32_t num_peers = file->num_peers;
    memcpy(peer_list, file->peer_list, num_peers * sizeof(peer_info_t));
    pthread_mutex_unlock(&file->lock);
    return num_peers;
}

uint32_t
get_block_status_list(file_state_t *file, block_status_t block_status[MAX_NUM_BLOCKS])
{
    pthread_mutex_lock(&file->lock);
    uint32_t num_blocks = file->meta.block_count;
    memcpy(block_status, file->block_status, num_blocks * sizeof(block_status_t));
    pthread_mutex_unlock(&file->lock);
    return num_blocks;
}

bool
get_block_data(file_state_t *file, uint32_t block_index, uint8_t *block_data)
{
    bool ok = false;
    pthread_mutex_lock(&file->lock);

    uint32_t num_blocks = file->meta.block_count;
    if (block_index >= num_blocks) {
        goto exit;
    }

    uint64_t block_size = file->meta.block_size;
    off_t offset = block_size * block_index;
    if (!read_block(file->file_fd, block_data, block_size, offset)) {
        goto exit;
    }

    ok = true;
 exit:
    pthread_mutex_unlock(&file->lock);
    return ok;
}
