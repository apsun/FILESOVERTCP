//for srand and drand
#define _XOPEN_SOURCE 500
#include "file.h"
#include "util.h"
#include "type.h"
#include "config.h"
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
#include <sys/time.h>

/**
 * Number of active files (length of files list).
 */
static int num_files;

/**
 * List of active files.
 */
static file_state_t files[MAX_NUM_FILES];

/**
 * Lock for num_files and the files array.
 */
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
    /* Not quite a GUID, but close enough */
    file_id_t id;
    for (int i = 0; i < 16; ++i) {
        id.bytes[i] = rand() % 256;
    }
    return id;
}

static void
file_id_to_string(const file_id_t *id, char str[32])
{
    for (size_t i = 0; i < 16; ++i) {
        sprintf(str + 2 * i, "%02x", id->bytes[i]);
    }
}

static bool
read_file_meta(int fd, file_meta_t *meta)
{
    if (!read_all(fd, &meta->id.bytes, sizeof(meta->id.bytes)))
        return false;

    if (!read_all(fd, &meta->file_name_len, sizeof(meta->file_name_len)))
        return false;

    if (meta->file_name_len > MAX_FILE_NAME_LEN)
        return false;

    if (!read_all(fd, meta->file_name, meta->file_name_len))
        return false;

    if (!read_all(fd, &meta->file_size, sizeof(meta->file_size)))
        return false;

    if (!read_all(fd, &meta->file_hash, sizeof(meta->file_hash)))
        return false;

    if (!read_all(fd, &meta->block_size, sizeof(meta->block_size)))
        return false;

    if (!read_all(fd, &meta->block_count, sizeof(meta->block_count)))
        return false;

    if (meta->block_count > MAX_NUM_BLOCKS)
        return false;

    /* WARNING: potentially unsafe reliance on padding */
    if (!read_all(fd, meta->block_hashes, meta->block_count * sizeof(sha256_t)))
        return false;

    return true;
}

static bool
write_file_meta(int fd, const file_meta_t *meta)
{
    if (!write_all(fd, &meta->id.bytes, sizeof(meta->id.bytes)))
        return false;

    if (!write_all(fd, &meta->file_name_len, sizeof(meta->file_name_len)))
        return false;

    if (!write_all(fd, meta->file_name, meta->file_name_len))
        return false;

    if (!write_all(fd, &meta->file_size, sizeof(meta->file_size)))
        return false;

    if (!write_all(fd, &meta->file_hash, sizeof(meta->file_hash)))
        return false;

    if (!write_all(fd, &meta->block_size, sizeof(meta->block_size)))
        return false;

    if (!write_all(fd, &meta->block_count, sizeof(meta->block_count)))
        return false;

    /* WARNING: potentially unsafe reliance on padding */
    if (!write_all(fd, meta->block_hashes, meta->block_count * sizeof(sha256_t)))
        return false;

    return true;
}

static bool
read_file_state(int fd, file_state_t *state)
{
    uint32_t magic;
    if (!read_all(fd, &magic, sizeof(magic)))
        return false;

    if (magic != FTCP_MAGIC)
        return false;

    if (!read_file_meta(fd, &state->meta))
        return false;

    if (!read_all(fd, &state->file_path_len, sizeof(state->file_path_len)))
        return false;

    if (!read_all(fd, state->file_path, state->file_path_len))
        return false;

    if (!read_all(fd, &state->state_path_len, sizeof(state->state_path_len)))
        return false;

    if (!read_all(fd, state->state_path, state->state_path_len))
        return false;

    /* WARNING: potentially unsafe reliance on padding */
    if (!read_all(fd, state->block_status, sizeof(block_status_t) * state->meta.block_count))
        return false;

    if (!read_all(fd, &state->num_peers, sizeof(state->num_peers)))
        return false;

    /* WARNING: potentially unsafe reliance on padding */
    if (!read_all(fd, state->peer_list, sizeof(peer_info_t) * state->num_peers))
        return false;

    return true;
}

static bool
write_file_state(int fd, const file_state_t *state)
{
    uint32_t magic = FTCP_MAGIC;
    if (!write_all(fd, &magic, sizeof(magic)))
        return false;

    if (!write_file_meta(fd, &state->meta))
        return false;

    if (!write_all(fd, &state->file_path_len, sizeof(state->file_path_len)))
        return false;

    if (!write_all(fd, state->file_path, state->file_path_len))
        return false;

    if (!write_all(fd, &state->state_path_len, sizeof(state->state_path_len)))
        return false;

    if (!write_all(fd, state->state_path, state->state_path_len))
        return false;

    /* WARNING: potentially unsafe reliance on padding */
    if (!write_all(fd, state->block_status, sizeof(block_status_t) * state->meta.block_count))
        return false;

    if (!write_all(fd, &state->num_peers, sizeof(state->num_peers)))
        return false;

    /* WARNING: potentially unsafe reliance on padding */
    if (!write_all(fd, state->peer_list, sizeof(peer_info_t) * state->num_peers))
        return false;

    return true;
}

static bool
create_file_meta(const char *file_path, file_meta_t *meta)
{
    bool ok = false;
    int fd = -1;
    uint8_t *data = NULL;

    /* Open file for reading */
    if ((fd = open(file_path, O_RDONLY, 0664)) < 0) {
        debuge("Failed to open file");
        goto cleanup;
    }

    /* Generate file ID */
    meta->id = generate_file_id();

    /* Get file name */
    size_t len = MAX_FILE_NAME_LEN;
    if (!get_file_name(meta->file_name, file_path, &len)) {
        debugf("Failed to copy file name -- too long?");
        goto cleanup;
    }
    meta->file_name_len = len;

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        debuge("Failed to stat file");
        goto cleanup;
    }
    meta->file_size = st.st_size;

    /* TODO: HASH ENTIRE FILE */
    (void)meta->file_hash;

    /* Calculate optimal block size */
    meta->block_size = calculate_block_size(meta->file_size);

    /* Total number of blocks */
    meta->block_count = (meta->file_size + (meta->block_size - 1)) / meta->block_size;

    /* Compute hashes for each block */
    data = malloc(meta->block_size);
    for (uint32_t i = 0; i < meta->block_count; ++i) {
        if (!read_block(fd, data, meta->block_size, i * meta->block_size)) {
            debugf("Failed to read block #%d", (i + 1));
            goto cleanup;
        }
        meta->block_hashes[i] = compute_sha256(meta->block_size, data);
    }

    ok = true;

cleanup:
    free(data);
    if (fd >= 0) {
        close(fd);
    }
    return ok;
}

static bool
create_file_state(const file_meta_t *meta, const char *file_path, block_status_t bs, file_state_t *state)
{
    /* Initialize metadata */
    state->meta = *meta;

    /* Initialize file path */
    size_t file_path_len = MAX_PATH_LEN;
    if (!copy_string(state->file_path, file_path, &file_path_len)) {
        debugf("Failed to copy file path");
        return false;
    }
    state->file_path_len = file_path_len;

    /* Initialize state file path */
    size_t state_path_len = MAX_PATH_LEN;
    /* TODO */

    /* Initialize block state list */
    for (int i = 0; i < MAX_NUM_BLOCKS; ++i) {
        state->block_status[i] = bs;
    }

    /* Initialize peer list */
    state->num_peers = 0;
    for (int i = 0; i < MAX_NUM_PEERS; ++i) {
        state->peer_list[i].ip_addr = 0;
        state->peer_list[i].port = 0;
    }

    return true;
}

static file_state_t *
add_file_to_tracker(file_state_t *file)
{
    pthread_mutex_lock(&lock);
    file_state_t *out = &files[num_files++];
    *out = *file;
    pthread_mutex_unlock(&lock);
    return out;
}

bool
add_remote_file(const file_meta_t *meta, file_state_t **file)
{
    bool ok = false;
    int fd = -1;

    /* Concatenate directory path + file name */
    char file_path[MAX_PATH_LEN];
    if (!format_string(file_path, MAX_PATH_LEN, "%s/%s", get_download_dir(), meta->file_name)) {
        debugf("File name too long");
        goto cleanup;
    }

    /* Initialize file state struct */
    file_state_t state;
    if (!create_file_state(meta, file_path, BS_DONT_HAVE, &state)) {
        debugf("Could not create file state");
        goto cleanup;
    }

    /* Open (create) the local file */
    fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        debuge("Could not open new file for writing");
        goto cleanup;
    }

    /* Expand it to the correct size */
    if (ftruncate(fd, meta->block_size * meta->block_count) < 0) {
        debuge("Could not set file length");
        goto cleanup;
    }

    /* Create state file */
    /* TODO */

    /* Add file to the tracker */
    *file = add_file_to_tracker(&state);
cleanup:
    if (fd >= 0) {
        close(fd);
    }
    return ok;
}

bool
add_local_file(const char *file_path, file_state_t **file)
{
    bool ok = false;

    /* Initialize metadata */
    file_meta_t meta;
    if (!create_file_meta(file_path, &meta)) {
        debugf("Failed to create file meta");
        return false;
    }

    /* Initialize file state struct */
    file_state_t state;
    if (!create_file_state(&meta, file_path, BS_DONT_HAVE, &state)) {
        debugf("Could not create file state");
        goto cleanup;
    }

cleanup:
    return ok;
}

void
set_block_status(file_state_t *file, uint32_t index, block_status_t bs)
{
    pthread_mutex_lock(&(file->lock));
    file->block_status[index] = bs;
    pthread_mutex_unlock(&(file->lock));
}

bool
initialize(void)
{
    const char *state_dir = get_state_dir();
    DIR *dp = opendir(state_dir);
    if (dp == NULL) {
        debuge("Cannot open state directory");
        return false;
    }

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        /* Skip non-state files */
        if (!has_file_extension(entry->d_name, STATE_FILE_EXT)) {
            continue;
        }

        /* Concatenate dir path + file name */
        char state_file_path[MAX_PATH_LEN];
        if (!format_string(state_file_path, MAX_PATH_LEN, "%s/%s", state_dir, entry->d_name)) {
            debugf("File path too long");
            continue;
        }

        /* Open state file */
        int fd = open(state_file_path, O_RDWR, 0664);
        if (fd < 0) {
            debuge("Could not open state file: %s", state_file_path);
            continue;
        }

        /* Read data into struct */
        file_state_t state;
        if (!read_file_state(fd, &state)) {
            debugf("Failed to read file state");
            close(fd);
            continue;
        }

        /* Add file to tracker */
        add_file_to_tracker(&state);
    }
    return true;
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
find_needed_block(file_state_t *file, uint8_t *block_bitmap, uint32_t * block_order, uint32_t *block_index)
{
    pthread_mutex_lock(&file->lock);
    uint32_t num_blocks = file->meta.block_count;
    for (uint32_t j = 0; j < num_blocks; ++j) {
        uint32_t i = block_order[j];
        if (file->block_status[i] != BS_DONT_HAVE) {
            continue;
        }
        uint32_t index = i / 8;
        uint32_t shift = i % 8;
        if ((block_bitmap[index] & (1 << shift)) != 0) {
            file->block_status[index] = BS_DOWNLOADING;
            *block_index = i;
            pthread_mutex_unlock(&file->lock);
            return true;
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

uint32_t *
generate_random_block_order(file_state_t *file)
{
    pthread_mutex_lock(&file->lock);
    uint32_t num_blocks = file->meta.block_count;
    pthread_mutex_unlock(&file->lock);
    uint32_t * ret = malloc(sizeof(uint32_t) * num_blocks);
    if(ret == NULL)
    {
        return ret;
    }
    for(uint32_t i = 0; i < num_blocks; ++i)
    {
        ret[i] = i;
    }
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int usec = tv.tv_usec;
    srand48(usec);
    size_t n = num_blocks;
    if (n > 1) {
        size_t i;
        for (i = n - 1; i > 0; i--) {
            size_t j = (unsigned int) (drand48()*(i+1));
            uint32_t t = ret[j];
            ret[j] = ret[i];
            ret[i] = t;
        }
    }
    return ret;    
}
