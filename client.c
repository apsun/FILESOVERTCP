#include "client.h"
#include "util.h"
#include "type.h"
#include "cmd.h"
#include "file.h"
#include "peer.h"
#include "io.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

typedef struct {
    /* Server ip and port */
    peer_info_t server;

    /* Port our server is listening on */
    uint16_t port;

    /* Socket connection to server */
    int sockfd;

    union {
        /* File state reference */
        file_state_t *file;

        /* File name (for initial connection) */
        const char *file_name;
    } u;
} client_state_t;

static void *
client_worker(void *arg);

static bool
client_get_peer_list(client_state_t *state)
{
    int fd = state->sockfd;
    file_state_t *file = state->u.file;

    /* Write request header */
    if (!cmd_write_request_header(fd, CMD_OP_GET_PEER_LIST)) {
        debugf("Failed to write request header");
        return false;
    }

    /* Write file ID */
    file_id_t id = file->meta.id;
    if (!write_file_id(cmd_write, fd, &id)) {
        debugf("Failed to write file ID");
        return false;
    }

    /* Write our server's port */
    if (!cmd_write(fd, &state->port, sizeof(state->port))) {
        debugf("Failed to write server port");
        return false;
    }

    /* Get response */
    uint32_t op, err;
    if (!cmd_read_response_header(fd, &op, &err)) {
        debugf("Failed to read response header");
        return false;
    }

    /* Check response op and error code */
    if (op != CMD_OP_GET_PEER_LIST || err != CMD_ERR_OK) {
        debugf("Response error: op(%08x), err(%08x)", op, err);
        return false;
    }

    /* Read number of peers */
    uint32_t num_peers;
    if (!cmd_read(fd, &num_peers, sizeof(num_peers))) {
        debugf("Failed to read number of peers");
        return false;
    }

    /* Read each peer */
    for (uint32_t i = 0; i < num_peers; ++i) {
        peer_info_t peer;
        if (!read_peer(cmd_read, fd, &peer)) {
            debugf("Failed to read peer");
            return false;
        }

        /* If we haven't seen this peer before, connect to it */
        /* TODO: This should go into a queue in the future */
        if (peer_add(file, peer)) {
            client_state_t *new_arg = malloc(sizeof(client_state_t));
            new_arg->server = peer;
            new_arg->u.file = file;
            new_arg->port = state->port;

            /* Spawn new thread for peer */
            pthread_t thread;
            if (pthread_create(&thread, NULL, client_worker, new_arg) < 0) {
                debuge("Failed to create new worker thread");
                free(new_arg);
                return false;
            }

            /* Try to detach new thread */
            if (pthread_detach(thread) < 0) {
                debuge("Failed to detach worker thread");
                /* Ignore, not a big deal (I think) */
            }
        }
    }

    debugf("GET_PEER_LIST successful");
    return true;
}

static bool
client_get_block_list(client_state_t *state, uint8_t block_bitmap[(MAX_NUM_BLOCKS + 7) / 8])
{
    int fd = state->sockfd;
    file_state_t *file = state->u.file;

    /* Write request header */
    if (!cmd_write_request_header(fd, CMD_OP_GET_BLOCK_LIST)) {
        debugf("Failed to write request header");
        return false;
    }

    /* Write file ID */
    file_id_t id = file->meta.id;
    if (!write_file_id(cmd_write, fd, &id)) {
        debugf("Failed to write file ID");
        return false;
    }

    /* Read response header */
    uint32_t op, err;
    if (!cmd_read_response_header(fd, &op, &err)) {
        debugf("Failed to read response header");
        return false;
    }

    /* Check op and error code */
    if (op != CMD_OP_GET_BLOCK_LIST || err != CMD_ERR_OK) {
        debugf("Response error: op(%08x), err(%08x)", op, err);
        return false;
    }

    /* Read bitmap size */
    uint32_t num_blocks;
    if (!cmd_read(fd, &num_blocks, sizeof(num_blocks))) {
        debugf("Failed to read bitmap size");
        return false;
    }

    /* Read bitmap */
    if (!cmd_read(fd, block_bitmap, (num_blocks + 7) / 8)) {
        debugf("Failed to read bitmap");
        return false;
    }

    debugf("GET_BLOCK_LIST successful");
    return true;
}

static bool
client_get_block_data(client_state_t *state, uint32_t block_index)
{
    int fd = state->sockfd;
    file_state_t *file = state->u.file;

    /* Write request header */
    if (!cmd_write_request_header(fd, CMD_OP_GET_BLOCK_DATA)) {
        debugf("Failed to write request header");
        return false;
    }

    /* Write file ID */
    file_id_t id = file->meta.id;
    if (!write_file_id(cmd_write, fd, &id)) {
        debugf("Failed to write file ID");
        return false;
    }

    /* Write block index */
    if (!cmd_write(fd, &block_index, sizeof(block_index))) {
        debugf("Failed to write block index");
        return false;
    }

    /* Read response header */
    uint32_t op, err;
    if (!cmd_read_response_header(fd, &op, &err)) {
        debugf("Failed to read response header");
        return false;
    }

    /* Check response op/err */
    if (op != CMD_OP_GET_BLOCK_DATA || err != CMD_ERR_OK) {
        debugf("Response error: op(%08x), err(%08x)", op, err);
        return false;
    }

    /* Read block size */
    uint64_t block_size;
    if (!cmd_read(fd, &block_size, sizeof(block_size))) {
        debugf("Failed to read block size");
        return false;
    }

    /* Validate block size */
    if (block_size != file->meta.block_size) {
        debugf("Block size mismatch");
        return false;
    }

    /* Read block contents */
    uint8_t *block_data = malloc(block_size);
    if (!cmd_read(fd, block_data, block_size)) {
        debugf("Failed to read block contents from socket");
        free(block_data);
        return false;
    }

    /* Check block data against correct hash */
    if (!check_block(file, block_index, block_data)) {
        debugf("Block hash mismatch");
        free(block_data);
        return false;
    }

    /* Write block to disk */
    if (!write_file_block(file, block_index, block_data)) {
        debugf("Failed to write block contents to disk");
        free(block_data);
        return false;
    }

    /* Clean up block buffer */
    free(block_data);

    /* Mark block as completed */
    set_block_status(file, block_index, BS_HAVE);

    debugf("GET_BLOCK_DATA successful (%u/%u)", block_index + 1, file->meta.block_count);
    return true;
}

static void
client_loop(client_state_t *state)
{
    file_state_t *file = state->u.file;
    uint8_t block_list[(MAX_NUM_BLOCKS + 7) / 8];
    bool got_block = false;
    while (!have_all_blocks(file) && client_get_peer_list(state)) {
        /* Get server's block list */
        if (!client_get_block_list(state, block_list)) {
            break;
        }

        /* Find out what we need */
        uint32_t block_index;
        while (find_needed_block(file, block_list, &block_index)) {
            if (!client_get_block_data(state, block_index)) {
                peer_remove(file, state->server);
                set_block_status(file, block_index, BS_DONT_HAVE);
                return;
            }
            got_block = true;
        }

        /* If server didn't have any new blocks, sleep a bit */
        if (!got_block) {
            sleep(15);
        }
        got_block = false;
    }
}

static bool
client_connect(client_state_t *state)
{
    int sockfd = -1;

    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        debuge("Failed to create TCP socket");
        return false;
    }

    /* Connect to server */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(state->server.port);
    addr.sin_addr.s_addr = htonl(state->server.ip_addr);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        debuge("Failed to connect to server");
        close(sockfd);
        return false;
    }

    /* Optimization */
    int i = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));

    /* Connection successful! */
    debugf("Connected to %s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    /* Write the magic bytes */
    if (!write_magic(cmd_write, sockfd)) {
        debugf("Failed to write FTCP_MAGIC");
        close(sockfd);
        return false;
    }

    /* Read response magic bytes */
    if (!read_magic(cmd_read, sockfd)) {
        debugf("Failed to read FTCP_MAGIC");
        close(sockfd);
        return false;
    }

    state->sockfd = sockfd;
    return true;
}

static void *
client_worker_new_file(void *arg)
{
    client_state_t *state = arg;
    if (!client_connect(state)) {
        goto cleanup;
    }
    int fd = state->sockfd;

    /* Write request header */
    if (!cmd_write_request_header(fd, CMD_OP_GET_FILE_META)) {
        debugf("Failed to write request header");
        goto cleanup;
    }

    /* Note the +1; the spec accounts for the NUL char */
    const char *str = state->u.file_name;
    uint32_t len = strlen(str) + 1;

    /* Write string */
    if (!write_string(cmd_write, fd, str, len)) {
        debugf("Failed to write string");
        goto cleanup;
    }

    /* Read response header */
    uint32_t op, err;
    if (!cmd_read_response_header(fd, &op, &err)) {
        debugf("Failed to read response header");
        goto cleanup;
    }

    /* Check op and error code */
    if (op != CMD_OP_GET_FILE_META || err != CMD_ERR_OK) {
        debugf("Response error: op(%08x), err(%08x)", op, err);
        goto cleanup;
    }

    /* Read the metadata */
    file_meta_t meta;
    if (!read_file_meta(cmd_read, fd, &meta)) {
        debugf("Failed to read file metadata");
        goto cleanup;
    }

    /* Write metadata to disk and add file to tracker */
    file_state_t *file;
    if (!add_remote_file(&meta, &file)) {
        debugf("Could not add new file");
        goto cleanup;
    }

    /* Add the server we just connected to inot the peer list */
    peer_add(file, state->server);

    /* Enter client loop */
    state->u.file = file;
    client_loop(state);

cleanup:
    debugf("Cleaning up client worker");
    if (state->sockfd >= 0) {
        close(state->sockfd);
    }
    free(state);
    return NULL;
}

static void *
client_worker(void *arg)
{
    client_state_t *state = arg;
    if (!client_connect(state)) {
        debugf("Failed to connect to server");
        goto cleanup;
    }

    /* Directly enter client loop */
    client_loop(state);

cleanup:
    debugf("Cleaning up client worker");
    if (state->sockfd >= 0) {
        close(state->sockfd);
    }
    free(state);
    return NULL;
}

bool
client_start(const char *ip_addr, uint16_t port, uint16_t server_port, const char *file_name)
{
    client_state_t *state = malloc(sizeof(client_state_t));
    if (!ipv4_atoi(ip_addr, &state->server.ip_addr)) {
        debugf("Invalid IP address: %s", ip_addr);
        return false;
    }
    state->server.port = port;
    state->u.file_name = file_name;
    state->sockfd = -1;
    state->port = server_port;

    pthread_t thread;
    if (pthread_create(&thread, NULL, client_worker_new_file, state) < 0) {
        debuge("Failed to create client thread");
        return false;
    }

    if (pthread_detach(thread) < 0) {
        debuge("Failed to detach client thread");
    }

    debugf("Started client thread");
    return true;
}


bool
client_resume(peer_info_t peer, uint16_t server_port, file_state_t *file)
{
    client_state_t *state = malloc(sizeof(client_state_t));
    state->server = peer;
    state->u.file = file;
    state->sockfd = -1;
    state->port = server_port;

    pthread_t thread;
    if (pthread_create(&thread, NULL, client_worker, state) < 0) {
        debuge("Failed to create client thread");
        return false;
    }

    if (pthread_detach(thread) < 0) {
        debuge("Failed to detach client thread");
    }

    debugf("Started client thread");
    return true;
}