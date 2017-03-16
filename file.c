#include "file.h"
#include "util.h"
#include "type.h"
#include "cmd.h"
#include "sha3.h"
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

static int num_files;
static file_state_t files[MAX_NUM_FILES];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t
calculate_block_size(uint64_t file_size)
{
    uint64_t block_size = MIN_BLOCK_SIZE;
    while (file_size / block_size > MAX_NUM_BLOCKS) {
        block_size *= 2;
    }
    return block_size;
}

static bool
file_id_equals(const file_id_t *a, const file_id_t *b)
{
    return memcmp(a, b, sizeof(file_id_t)) == 0;
}

static bool
sha256_equals(const sha256_t *a, const sha256_t *b)
{
    return memcmp(a, b, sizeof(sha256_t)) == 0;
}

static sha256_t
compute_sha256(uint64_t block_size, uint8_t *block_data)
{
    sha256_t checksum;
    sha3(block_data, block_size, checksum.digest, sizeof(checksum.digest));
    return checksum;
}

static file_id_t
generate_file_id(void)
{
    file_id_t id;
    for (int i = 0; i < 16; ++i) {
        id.bytes[i] = rand() % 256;
    }
    return id;
}

static file_meta_t
generate_file_meta(const char *file_path)
{
    /* TODO */
    file_meta_t meta;
    return meta;
}

static bool
set_block_status_impl(file_state_t *file, uint32_t index, block_status_t bs)
{
    /* TODO: Update the status of the block file on disk */

    file->block_status[index] = bs;
    return true;
}

bool
set_block_status(file_state_t *file, uint32_t index, block_status_t bs)
{
    pthread_mutex_lock(&(file->lock));
    bool ok = set_block_status_impl(file, index, bs);
    pthread_mutex_unlock(&(file->lock));
    return ok;
}

bool
add_directory(const char *dir_path)
{
    DIR *dp = opendir(dir_path);
    if (dp == NULL) {
        debuge("Cannot open directory");
        return false;
    }

    pthread_mutex_lock(&lock);
    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        /* Skip current/parent directory entries */
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Skip metadata and block info files */
        if (has_file_extension(entry->d_name, META_FILE_EXT) ||
            has_file_extension(entry->d_name, BLOCK_FILE_EXT)) {
            continue;
        }

        /* Open file */
        char file_path[4096];
        sprintf(file_path, "%s/%s", dir_path, entry->d_name);
        int fd = open(file_path, O_RDWR, 0664);
        if (fd < 0) {
            debuge("Could not open file: %s", file_path);
            continue;
        }

        /* See if it already has a metadata file */
        char meta_path[4096];
        sprintf(meta_path, "%s%s", file_path, META_FILE_EXT);
        int meta_fd = open(file_path, O_RDONLY, 0664);
        if (meta_fd < 0) {
            /* Generate and write a new metadata file */
        }

        /* See if it already has a block info file */
        char block_path[4096];
        sprintf(block_path, "%s%s", file_path, BLOCK_FILE_EXT);
        int block_fd = open(block_path, O_RDWR, 0664);
        if (block_fd < 0) {
            /* Generate a new block info file */
        }

        files[num_files].file_fd = fd;

        struct stat buf;
        fstat(files[num_files].file_fd, &buf);
        files[num_files].meta.magic = FTCP_MAGIC;
        files[num_files].meta.file_name_len = strlen(entry->d_name) + 1;
        files[num_files].meta.file_size = buf.st_size;
        files[num_files].meta.block_size = calculate_block_size(files[num_files].meta.file_size);
        files[num_files].meta.block_count = (files[num_files].meta.file_size % files[num_files].meta.block_size) ? (files[num_files].meta.file_size / files[num_files].meta.block_size) + 1 : (files[num_files].meta.file_size / files[num_files].meta.block_size);
        //filelist[files].file_hash = ?
        files[num_files].meta.id = generate_file_id();
        for(size_t i = 0; i < files[num_files].meta.file_name_len; i++)
        {
            files[num_files].meta.file_name[i] = entry->d_name[i]; // gets the file name and sets it.
        }
        for(size_t i = 0; i < files[num_files].meta.block_count; i++)
        {
            //filelist[files].block_hashes[i] = ?; dont know how to hash.
            files[num_files].block_status[i] = BS_HAVE; //we have everthing
        }
        pthread_mutex_init(&files[num_files].lock, NULL);
        num_files++;
    }
    pthread_mutex_unlock(&lock);
    return true;
}

file_state_t *
add_file(file_meta_t *meta)
{
    int fd = open(meta->file_name, O_CREAT | O_RDWR, 0664);
    if (fd < 0) {
        debuge("Failed to open file: %s", meta->file_name);
        return NULL;
    }

    pthread_mutex_lock(&lock);
    file_state_t *file = &files[num_files++];

    /* Initialize file structure */
    pthread_mutex_init(&file->lock, NULL);
    file->meta = *meta;
    file->file_fd = fd;
    file->num_peers = 0;
    for (int i = 0; i < MAX_NUM_BLOCKS; ++i) {
        file->block_status[i] = BS_DONT_HAVE;
    }
    for (int i = 0; i < MAX_NUM_PEERS; ++i) {
        file->peer_list[i].ip_addr = 0;
        file->peer_list[i].port = 0;
    }
    /* TODO: block_info_fd */

    pthread_mutex_unlock(&lock);
    return file;
}

file_state_t *
create_local_file(file_meta_t * meta)
{
    return add_file(meta);
}

bool
get_file_by_name(const char *file_name, file_state_t **out_file)
{
    pthread_mutex_lock(&lock);
    for (int i = 0; i < num_files; ++i) {
        if (strcmp(file_name, files[i].meta.file_name) == 0) {
            *out_file = &files[i];
            pthread_mutex_unlock(&lock);
            return true;
        }
    }
    pthread_mutex_unlock(&lock);
    return false;
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

bool
find_needed_block(file_state_t *file, uint8_t *block_bitmap, uint32_t *block_index)
{
    pthread_mutex_lock(&file->lock);
    uint32_t num_blocks = file->meta.block_count;
    for (uint32_t i = 0; i < num_blocks; ++i) {
        if (file->block_status[i] == BS_HAVE) {
            continue;
        }
        uint32_t index = i / 8;
        uint32_t shift = i % 8;
        if ((block_bitmap[index] & (1 << shift)) != 0) {
            bool ok = set_block_status_impl(file, i, BS_DOWNLOADING);
            *block_index = i;
            pthread_mutex_unlock(&file->lock);
            return ok;
        }
    }
    pthread_mutex_unlock(&file->lock);
    return false;
}

bool
check_block(file_state_t *file, uint32_t block_index, uint8_t *block_data)
{
    sha256_t checksum = compute_sha256(file->meta.block_size, block_data);
    sha256_t expected = file->meta.block_hashes[block_index];
    return sha256_equals(&checksum, &expected);
}
