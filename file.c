//for srand and drand
#define _XOPEN_SOURCE 500
#include "file.h"
#include "util.h"
#include "type.h"
#include "config.h"
#include "cmd.h"
#include "sha3.h"
#include "io.h"
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
    return memcmp(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

static bool
sha256_equals(const sha256_t *a, const sha256_t *b)
{
    return memcmp(a->digest, b->digest, sizeof(a->digest)) == 0;
}

static char *
file_id_to_str(const file_id_t *id, char buf[33])
{
    for (int i = 0; i < 16; ++i) {
        sprintf(buf + 2 * i, "%02x", id->bytes[i]);
    }
    return buf;
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
    meta->file_name_len = len + 1;

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        debuge("Failed to stat file");
        goto cleanup;
    }
    meta->file_size = st.st_size;

    /* TODO: HASH ENTIRE FILE */
    for (int i = 0; i < 32; ++i) {
        meta->file_hash.digest[i] = 0;
    }

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
create_file_state(
    const file_meta_t *meta,
    const char *file_path,
    const char *state_path,
    block_status_t bs,
    file_state_t *state)
{
    /* Initialize metadata */
    state->meta = *meta;

    /* Initialize file path */
    size_t file_path_len = MAX_PATH_LEN;
    if (!copy_string(state->file_path, file_path, &file_path_len)) {
        debugf("Failed to copy file path");
        return false;
    }
    state->file_path_len = file_path_len + 1;

    /* Initialize state file path */
    size_t state_path_len = MAX_PATH_LEN;
    if (!copy_string(state->state_path, state_path, &state_path_len)) {
        debugf("Failed to copy state file path");
        return false;
    }
    state->state_path_len = state_path_len + 1;

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
add_file_to_tracker(file_state_t *file, int file_fd, int state_file_fd)
{
    pthread_mutex_lock(&lock);
    file_state_t *out = &files[num_files++];
    *out = *file;
    pthread_mutex_init(&out->lock, NULL);
    out->file_fd = file_fd;
    out->state_file_fd = state_file_fd;
    pthread_mutex_unlock(&lock);
    return out;
}

bool
add_remote_file(const file_meta_t *meta, file_state_t **file)
{
    bool ok = false;
    int fd = -1;
    int state_fd = -1;

    /* Concatenate directory path + file name */
    char file_path[MAX_PATH_LEN];
    if (!format_string(file_path, MAX_PATH_LEN, "%s/%s", get_download_dir(), meta->file_name)) {
        debugf("File name too long");
        goto cleanup;
    }

    /* Convert file ID to hex string */
    char id_str[33];
    file_id_to_str(&meta->id, id_str);

    /* Concatenate state dir path + file name + extension */
    char state_path[MAX_PATH_LEN];
    if (!format_string(state_path, MAX_PATH_LEN, "%s/%s%s", get_state_dir(), id_str, STATE_FILE_EXT)) {
        debugf("State file name too long");
        goto cleanup;
    }

    /* Check if state file already exists */
    if (access(state_path, F_OK) >= 0) {
        debugf("State file already exists");
        goto cleanup;
    }

    /* Initialize file state struct */
    file_state_t state;
    if (!create_file_state(meta, file_path, state_path, BS_DONT_HAVE, &state)) {
        debugf("Could not create file state");
        goto cleanup;
    }

    /* Open (create) the local file */
    fd = open(file_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        debuge("Could not open new file for writing");
        goto cleanup;
    }

    /* Expand it to the correct size */
    if (ftruncate(fd, meta->file_size) < 0) {
        debuge("Could not set file length");
        goto cleanup;
    }

    /* Create state file */
    state_fd = open(state.state_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (state_fd < 0) {
        debuge("Could not create state file");
        goto cleanup;
    }

    /* Add file to the tracker */
    *file = add_file_to_tracker(&state, fd, state_fd);
    return true;

cleanup:
    if (state_fd >= 0) {
        close(state_fd);
    }
    if (fd >= 0) {
        close(fd);
    }
    return ok;
}

bool
add_local_file(const char *file_path, file_state_t **file)
{
    bool ok = false;
    int fd = -1;
    int state_fd = -1;

    /* Initialize metadata */
    file_meta_t meta;
    if (!create_file_meta(file_path, &meta)) {
        debugf("Failed to create file meta");
        goto cleanup;
    }

    /* Convert file ID to hex string */
    char id_str[33];
    file_id_to_str(&meta.id, id_str);

    /* Concatenate state dir path + file name + extension */
    char state_path[MAX_PATH_LEN];
    if (!format_string(state_path, MAX_PATH_LEN, "%s/%s%s", get_state_dir(), id_str, STATE_FILE_EXT)) {
        debugf("State file name too long");
        goto cleanup;
    }

    /* Check if state file already exists */
    if (access(state_path, F_OK) >= 0) {
        debugf("State file already exists");
        goto cleanup;
    }

    /* Initialize file state struct */
    file_state_t state;
    if (!create_file_state(&meta, file_path, state_path, BS_HAVE, &state)) {
        debugf("Could not create file state");
        goto cleanup;
    }

    /* Open (create) the local file */
    fd = open(file_path, O_RDWR, 0644);
    if (fd < 0) {
        debuge("Could not open new file for writing");
        goto cleanup;
    }

    /* Create state file */
    state_fd = open(state.state_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (state_fd < 0) {
        debuge("Could not create state file");
        goto cleanup;
    }

    /* Add file to tracker */
    *file = add_file_to_tracker(&state, fd, state_fd);
    return true;

cleanup:
    if (state_fd >= 0) {
        close(state_fd);
    }
    if (fd >= 0) {
        close(fd);
    }
    return ok;
}

void
set_block_status(file_state_t *file, uint32_t index, block_status_t bs)
{
    pthread_mutex_lock(&(file->lock));
    file->block_status[index] = bs;
    pthread_mutex_unlock(&(file->lock));
}

void
remove_downloading_blocks(file_state_t *file)
{
    pthread_mutex_lock(&(file->lock));
    uint32_t num_blocks = file->meta.block_count;
    for (uint32_t i = 0; i < num_blocks; ++i) {
        if (file->block_status[i] == BS_DOWNLOADING) {   
            file->block_status[i] = BS_DONT_HAVE;
        }
    }
    pthread_mutex_unlock(&(file->lock));
}

bool
write_file_block(file_state_t *file, uint32_t block_index, uint8_t *block_data)
{
    size_t count = file->meta.block_size;

    /* Truncate last block */
    if (block_index == file->meta.block_count - 1) {
        count = file->meta.file_size - block_index * file->meta.block_size;
    }

    off_t offset = block_index * file->meta.block_size;
    return write_block(file->file_fd, block_data, count, offset);
}

bool
initialize(void)
{
    const char *state_dir = get_state_dir();
    const char *dl_dir = get_download_dir();

    /* Create the state + download dirs at startup */
    /* TODO: May need to recursively create */
    mkdir(state_dir, 0755);
    mkdir(dl_dir, 0755);

    /* Open and read state files in state dir */
    DIR *dp = opendir(state_dir);
    if (dp == NULL) {
        debuge("Cannot open state directory");
        return false;
    }

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        /* Skip entries w/o our extension */
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
        int state_fd = open(state_file_path, O_RDWR, 0664);
        if (state_fd < 0) {
            debuge("Could not open state file: %s", state_file_path);
            continue;
        }

        /* Check magic bytes */
        if (!read_magic(read_all, state_fd)) {
            debugf("Magic mismatch");
            close(state_fd);
            continue;
        }

        /* Read data into struct */
        file_state_t state;
        if (!read_file_state(read_all, state_fd, &state)) {
            debugf("Failed to read file state");
            close(state_fd);
            continue;
        }

        /* Open file */
        int fd = open(state.file_path, O_RDWR, 0644);
        if (fd < 0) {
            debuge("Could not open file: %s", state.file_path);
            close(state_fd);
        }

        /* Add file to tracker */
        add_file_to_tracker(&state, fd, state_fd);
    }

    closedir(dp);
    return true;
}

bool
flush(void)
{
    pthread_mutex_lock(&lock);
    for (int i = 0; i < num_files; ++i) {
        pthread_mutex_lock(&files[i].lock);
        int state_fd = files[i].state_file_fd;
        lseek(state_fd, 0, SEEK_SET);
        write_magic(write_all, state_fd);
        write_file_state(write_all, state_fd, &files[i]);
        fsync(state_fd);
        fsync(files[i].file_fd);
        pthread_mutex_unlock(&files[i].lock);
    }
    pthread_mutex_unlock(&lock);
    return true;
}

bool
finalize(void)
{
    pthread_mutex_lock(&lock);
    for (int i = 0; i < num_files; ++i) {
        pthread_mutex_lock(&files[i].lock);
        close(files[i].state_file_fd);
        close(files[i].file_fd);
        files[i].state_file_fd = -1;
        files[i].file_fd = -1;
        pthread_mutex_unlock(&files[i].lock);
    }
    pthread_mutex_unlock(&lock);
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

bool
get_file_by_index(int index, file_state_t **out_file)
{
    bool ok = false;
    pthread_mutex_lock(&lock);
    if (index >= 0 && index < num_files) {
        *out_file = &files[index];
        ok = true;
    }
    pthread_mutex_unlock(&lock);
    return ok;
}

int
get_num_files()
{
    pthread_mutex_lock(&lock);
    int ret = num_files;
    pthread_mutex_unlock(&lock);
    return ret;
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
have_all_blocks(file_state_t *file)
{
    pthread_mutex_lock(&file->lock);
    bool ok = true;
    uint32_t num_blocks = file->meta.block_count;
    for (uint32_t i = 0; i < num_blocks; ++i) {
        if (file->block_status[i] != BS_HAVE) {
            ok = false;
            break;
        }
    }
    pthread_mutex_unlock(&file->lock);
    return ok;
}

bool
find_needed_block(file_state_t *file, uint8_t *block_bitmap, uint32_t *block_index)
{
    uint32_t blocks_found = 0;
    uint32_t block_needed[MAX_NUM_BLOCKS];
    pthread_mutex_lock(&file->lock);
    uint32_t num_blocks = file->meta.block_count;
    for (uint32_t i = 0; i < num_blocks; ++i) {
        /* Find a block we need */
        if (file->block_status[i] != BS_DONT_HAVE) {
            continue;
        }

        /* Check if server has that block */
        uint32_t index = i / 8;
        uint32_t shift = i % 8;
        if ((block_bitmap[index] & (1 << shift)) != 0) {
            block_needed[blocks_found++] = i;
        }
    }

    /* Randomize block order */
    if (blocks_found == 0) {
        pthread_mutex_unlock(&file->lock);
        return false;
    } else {
        uint32_t index = block_needed[rand() % blocks_found];
        *block_index = index;
        file->block_status[index] = BS_DOWNLOADING;
        pthread_mutex_unlock(&file->lock);
        return true;
    }
}

bool
check_block(file_state_t *file, uint32_t block_index, uint8_t *block_data)
{
    sha256_t hash = compute_sha256(file->meta.block_size, block_data);
    sha256_t expected = file->meta.block_hashes[block_index];
    return sha256_equals(&hash, &expected);
}
