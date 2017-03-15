#include "client.h"
#include "server.h"
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
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    /* Server ip and port */
    peer_info_t server;

    /* Socket connection to server */
    int sockfd;

    union {
        /* File state reference */
        file_state_t *file;

        /* File name (for initial connection) */
        const char *file_name;
    } u;
} client_state_t;

static bool
client_get_peer_list(client_state_t *state)
{
    int fd = state->sockfd;
    file_state_t *file = state->u.file;

    /* Write request header */
    if (!cmd_write_request_header(fd, CMD_OP_GET_PEER_LIST)) {
        return false;
    }

    /* Write file ID */
    file_id_t id = state->file->meta.id;
    if (!cmd_write(fd, &state->file->meta.id, sizeof(state->file->meta.id))) {
        return false;
    }

    /* Get response */
    uint32_t op, err;
    if (!cmd_read_response_header(fd, &op, &err)) {
        return false;
    }

    /* Check response op and error code */
    if (op != CMD_OP_GET_PEER_LIST || err != CMD_ERR_OK) {
        return false;
    }

    /* Read number of peers */
    uint32_t num_peers;
    if (!cmd_read(fd, &num_peers, sizeof(num_peers))) {
        return false;
    }

    /* Read each peer */
    for (uint32_t i = 0; i < num_peers; ++i) {
        peer_info_t peer;

        /* Read peer IP */
        if (!cmd_read(fd, &peer.ip_addr, sizeof(peer.ip_addr))) {
            return false;
        }

        /* Read peer port */
        if (!cmd_read(fd, &peer.port, sizeof(peer.port))) {
            return false;
        }

        /* If we haven't seen this peer before, connect to it */
        /* TODO: This should go into a queue in the future */
        if (add_new_peer(file, peer)) {
            client_state_t *new_arg = malloc(sizeof(client_state_t));
            new_arg->server = server;
            new_arg->u.file = file;

            /* Spawn new thread for peer */
            pthread_t thread;
            if (pthread_create(&thread, NULL, client_worker, new_arg) < 0) {
                perror("Failed to create new worker thread");
                free(new_arg);
                return false;
            }

            /* Try to detach new thread */
            if (pthread_detach(thread) < 0) {
                perror("Failed to detach worker thread");
                /* Ignore, not a big deal (I think) */
            }
        }
    }

    return true;
}

static bool
client_get_block_list(client_state_t *state, uint8_t block_bitmap[(MAX_NUM_BLOCKS + 7) / 8])
{
    int fd = state->sockfd;
    file_state_t *file = state->u.file;

    /* Write request header */
    if (!cmd_write_request_header(fd, CMD_OP_GET_BLOCK_LIST)) {
        return false;
    }

    /* Write file ID */
    file_id_t id = state->file->meta.id;
    if (!cmd_write(fd, &state->file->meta.id, sizeof(state->file->meta.id))) {
        return false;
    }

    /* Read response header */
    uint32_t op, err;
    if (!cmd_read_response_header(fd, &op, &err)) {
        return false;
    }

    /* Check op and error code */
    if (op != CMD_OP_GET_BLOCK_LIST || err != CMD_ERR_OK) {
        return false;
    }

    /* Read bitmap size */
    uint32_t num_blocks;
    if (!cmd_read(fd, &num_blocks, sizeof(num_blocks))) {
        return false;
    }

    /* Read bitmap */
    if (!cmd_read(fd, block_bitmap, (num_blocks + 7) / 8)) {
        return false;
    }

    return true;
}

static bool
client_get_block_data(client_state_t *state, uint32_t block_index)
{
    int fd = state->sockfd;

    /* Write request header */
    if (!cmd_write_request_header(fd, CMD_OP_GET_BLOCK_DATA)) {
        return false;
    }

    /* Write file ID */
    file_id_t id = state->file->meta.id;
    if (!cmd_write(fd, &state->file->meta.id, sizeof(state->file->meta.id))) {
        return false;
    }

    /* Write block index */
    if (!cmd_write(fd, &block_index, sizeof(block_index))) {
        return false;
    }

    /* Read response header */
    uint32_t op, err;
    if (!cmd_read_response_header(fd, &op, &err)) {
        return false;
    }

    /* Check response op/err */
    if (op != CMD_OP_GET_BLOCK_DATA || err != CMD_ERR_OK) {
        return false;
    }

    /* Read block size */
    uint32_t block_size;
    if (!cmd_read(fd, &block_size, sizeof(block_size))) {
        return false;
    }

    /* Read block contents */
    uint8_t *block_data = malloc(block_size);
    if (!cmd_read(fd, block_data, block_size)){
        free(block_data);
        return false;
    }

    /* Write block to disk */
    off_t offset = block_index * block_size;
    if (!write_block(file->file_fd, blockdata, block_size, offset)) {
        free(block_data);
        return false;
    }

    free(block_data);

    /* Mark block as completed */
    if (!mark_block(file, block_index, BS_HAVE)) {
        return false;
    }

    return true;
}

static void
client_loop(client_state_t *state)
{
    uint8_t block_list[(MAX_NUM_BLOCKS + 7) / 8];
    char *block_list = NULL;
    while (client_get_peer_list(state)) {
        if (!client_get_block_list(state, block_list)) {
            break;
        }

        uint32_t block_index;
        while (find_needed_block(state->file, block_list, &block_index)) {
            if (!client_get_block_data(state, block_index)) {
                remove_peer(file, state->server);
                mark_block(file, block_index, BS_DONT_HAVE);
                goto cleanup;
            }
        }
    }
}

static bool
client_connect(client_state_t *state)
{
    int sockfd = -1;

    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Failed to create TCP socket");
        return false;
    }

    /* Connect to server */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(state->server_port);
    addr.sin_addr.s_addr = htonl(state->server_ip);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to connect to server");
        close(sockfd);
        return false;
    }

    /* Connection successful! */
    printf("Connected to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    /* Write and the magic bytes */
    uint32_t magic = FTCP_MAGIC;
    if (!cmd_write(fd, &magic, sizeof(magic))) {
        printe("Failed to write FTCP_MAGIC\n");
        close(sockfd);
        return false;
    }

    /* Read magic from server */
    if (!cmd_read(fd, &magic, sizeof(magic))) {
        printe("Failed to read FTCP_MAGIC\n");
        close(sockfd);
        return false;
    }

    /* Check magic match */
    if (magic != FTCP_MAGIC) {
        printe("Magic mismatch, expected FTCP_MAGIC, got 0x%08x\n", magic);
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

    /* Write request header */
    if (!cmd_write_request_header(fd, CMD_OP_GET_FILE_META)) {
        printe("Failed to write request header\n");
        goto cleanup;
    }

    /* Note the +1; the spec accounts for the NUL char */
    char *str = file->u.file_name;
    uint32_t len = strlen(str) + 1;

    /* Write string length */
    if (!cmd_write(fd, &len, sizeof(len))) {
        printe("Failed to write string length\n");
        goto cleanup;
    }

    /* Write string contents */
    if (!cmd_write(fd, str, len)) {
        printe("Failed to write string\n");
        goto cleanup;
    }

    /* Read response header */
    uint32_t op, err;
    if (!cmd_read_response_header(fd, &op, &err)) {
        printe("Failed to read response header\n");
        goto cleanup;
    }

    /* Check op and error code */
    if (op != CMD_OP_GET_FILE_META || err != CMD_ERR_OK) {
        printe("Response error: op(%08x), err(%08x)\n", op, err);
        goto cleanup;
    }

    /* Read the metadata */
    file_meta_t meta;
    if (!cmd_read(fd, &meta, sizeof(meta))) {
        printe("Failed to read file metadata\n");
        goto cleanup;
    }

    /* Write metadata to disk and add file to tracker */
    file_state_t *file = create_local_file(&meta);

    /* Enter client loop */
    state->u.file = file;
    client_loop(state);

 cleanup:
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
        goto cleanup;
    }

    /* Directly enter client loop */
    client_loop(state);

cleanup:
    if (state->sockfd >= 0) {
        close(state->sockfd);
    }
    free(state);
    return NULL;
}

void
client_run(uint32_t ip_addr, uint16_t port, const char *file_name)
{
    client_state_t *state = malloc(sizeof(client_state_t));
    state->server.ip_addr = ip_addr;
    state->server.port = port;
    state->u.file_name = file_name;
    state->sockfd = -1;

    pthread_t thread;
    if (pthread_create(&thread, NULL, client_worker_new_file, state) < 0) {
        perror("Failed to create client thread");
        return 1;
    }

    if (pthread_detach(thread) < 0) {
        perror("Failed to detach client thread");
        return 1;
    }

    return 0;
}
