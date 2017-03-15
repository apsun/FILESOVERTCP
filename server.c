#include "server.h"
#include "util.h"
#include "type.h"
#include "cmd.h"
#include "file.h"
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

typedef struct {
    uint16_t port;
} server_arg_t;

typedef struct {
    int asockfd;
    uint32_t client_ip;
    /* TODO: More stuff here... */
} server_state_t;

static bool
server_handle_get_file_meta(server_state_t *state)
{
    const uint32_t op = CMD_OP_GET_FILE_META;
    int fd = state->asockfd;

    /* Read file name length */
    uint32_t file_name_len;
    if (!cmd_read(fd, &file_name_len, sizeof(file_name_len))) {
        cmd_write_response_header(fd, op, CMD_ERR_MALFORMED);
        return false;
    }

    /* Validate file name length */
    if (file_name_len == 0 || file_name_len > MAX_FILE_NAME_LEN) {
        cmd_write_response_header(fd, op, CMD_ERR_MALFORMED);
        return false;
    }

    /* Read file name */
    char file_name[MAX_FILE_NAME_LEN];
    if (!cmd_read(fd, file_name, file_name_len)) {
        cmd_write_response_header(fd, op, CMD_ERR_MALFORMED);
        return false;
    }

    /* Ensure we have a NUL terminator */
    if (file_name[file_name_len - 1] != '\0') {
        cmd_write_response_header(fd, op, CMD_ERR_MALFORMED);
        return false;
    }

    /* Check for embedded NUL characters */
    if (strlen(file_name) != file_name_len - 1) {
        cmd_write_response_header(fd, op, CMD_ERR_FILE_NOT_FOUND);
        return false;
    }

    /* Checks to see if we have the file */
    file_state_t *file;
    if (!get_file_by_name(file_name, &file)) {
        cmd_write_response_header(fd, op, CMD_ERR_FILE_NOT_FOUND);
        return false;
    }

    /* Write response header */
    if (!cmd_write_response_header(fd, op, CMD_ERR_OK)) {
        return false;
    }

    /* Write response */
    if (!cmd_write(fd, &file->meta, sizeof(file->meta))) {
        return false;
    }

    return true;
}

static bool
server_handle_get_peer_list(server_state_t *state)
{
    const uint32_t op = CMD_OP_GET_PEER_LIST;
    int fd = state->asockfd;

    /* Read file ID */
    file_id_t file_id;
    if (!cmd_read(fd, &file_id, sizeof(file_id))) {
        cmd_write_response_header(fd, op, CMD_ERR_MALFORMED);
        return false;
    }

    /* Get file state */
    file_state_t *file;
    if (!get_file_by_id(&file_id, &file)) {
        cmd_write_response_header(fd, op, CMD_ERR_FILE_NOT_FOUND);
        return false;
    }

    /* Get peer list */
    peer_info_t peer_list[MAX_NUM_PEERS];
    uint32_t num_peers = get_peer_list(file, peer_list);

    /* Write response header */
    if (!cmd_write_response_header(fd, op, CMD_ERR_OK)) {
        return false;
    }

    /* Write number of peers */
    if (!cmd_write(fd, &num_peers, sizeof(num_peers))) {
        return false;
    }

    /* Write each peer's IP address */
    for (uint32_t i = 0; i < num_peers; ++i) {
        uint32_t peer_ip = peer_list[i].ip_addr;
        uint16_t peer_port = peer_list[i].port;
        if (!cmd_write(fd, &peer_ip, sizeof(peer_ip))) {
            return false;
        }
        if (!cmd_write(fd, &peer_port, sizeof(peer_port))) {
            return false;
        }
    }

    return true;
}

static bool
server_handle_get_block_list(server_state_t *state)
{
    const uint32_t op = CMD_OP_GET_BLOCK_LIST;
    int fd = state->asockfd;

    /* Read file ID */
    file_id_t file_id;
    if (!cmd_read(fd, &file_id, sizeof(file_id))) {
        cmd_write_response_header(fd, op, CMD_ERR_MALFORMED);
        return false;
    }

    /* Get file state */
    file_state_t *file;
    if (!get_file_by_id(&file_id, &file)) {
        cmd_write_response_header(fd, op, CMD_ERR_FILE_NOT_FOUND);
        return false;
    }

    /* Get status of all blocks */
    block_status_t block_status[MAX_NUM_BLOCKS];
    uint32_t num_blocks = get_block_status_list(file, block_status);

    /* Write response header */
    if (!cmd_write_response_header(fd, op, CMD_ERR_OK)) {
        return false;
    }

    /* Write the size of the bitmap */
    if (!cmd_write(fd, &num_blocks, sizeof(num_blocks))) {
        return false;
    }

    /* Write block bitmap */
    for (uint32_t i = 0; i < num_blocks; i += 8) {
        /* Pack bits. 1 = have, 0 = otherwise */
        uint8_t packed = 0;
        for (int j = 0; j < 8 && i + j < num_blocks; ++j) {
            if (block_status[i + j] == BS_HAVE) {
                packed |= (1 << j);
            }
        }

        /* Write bitmap chunk */
        if (!cmd_write(fd, &packed, sizeof(packed))) {
            return false;
        }
    }

    return true;
}

static bool
server_handle_get_block_data(server_state_t *state)
{
    bool ok = false;
    uint8_t *block_data = NULL;
    const uint32_t op = CMD_OP_GET_BLOCK_DATA;
    int fd = state->asockfd;

    /* Read file ID */
    file_id_t file_id;
    if (!cmd_read(fd, &file_id, sizeof(file_id))) {
        cmd_write_response_header(fd, op, CMD_ERR_MALFORMED);
        goto cleanup;
    }

    /* Read block index */
    uint32_t block_index;
    if (!cmd_read(fd, &block_index, sizeof(block_index))) {
        cmd_write_response_header(fd, op, CMD_ERR_MALFORMED);
        goto cleanup;
    }

    /* Get file state */
    file_state_t *file;
    if (!get_file_by_id(&file_id, &file)) {
        cmd_write_response_header(fd, op, CMD_ERR_FILE_NOT_FOUND);
        goto cleanup;
    }

    /* Allocate space to hold the block */
    block_data = malloc(file->meta.block_size);
    if (block_data == NULL) {
        cmd_write_response_header(fd, op, CMD_ERR_UNKNOWN);
        goto cleanup;
    }

    /* Read the data from the block */
    if (!get_block_data(file, block_index, block_data)) {
        cmd_write_response_header(fd, op, CMD_ERR_BLOCK_NOT_FOUND);
        goto cleanup;
    }

    /* Write response header */
    if (!cmd_write_response_header(fd, op, CMD_ERR_OK)) {
        goto cleanup;
    }

    /* Write size of block */
    if (!cmd_write(fd, &file->meta.block_size, sizeof(file->meta.block_size))) {
        goto cleanup;
    }

    /* Write block contents */
    if (!cmd_write(fd, block_data, file->meta.block_size)) {
        goto cleanup;
    }

    ok = true;

cleanup:
    free(block_data);
    return ok;
}

static bool
server_handle_op(server_state_t *state, uint32_t op)
{
    switch (op) {
    case CMD_OP_GET_FILE_META:
        return server_handle_get_file_meta(state);
    case CMD_OP_GET_PEER_LIST:
        return server_handle_get_peer_list(state);
    case CMD_OP_GET_BLOCK_LIST:
        return server_handle_get_block_list(state);
    case CMD_OP_GET_BLOCK_DATA:
        return server_handle_get_block_data(state);
    default:
        return false;
    }
}

static void *
server_worker(void *arg)
{
    server_state_t *state = arg;

    /* Read and check the magic bytes */
    uint32_t magic;
    if (!cmd_read(state->asockfd, &magic, sizeof(magic))) {
        printe("Failed to read FTCP_MAGIC\n");
        goto cleanup;
    }

    if (magic != FTCP_MAGIC) {
        printe("Magic mismatch, expected FTCP_MAGIC, got 0x%08x\n", magic);
        goto cleanup;
    }

    /* Respond with our own magic bytes */
    if (!cmd_write(state->asockfd, &magic, sizeof(magic))) {
        printe("Failed to write FTCP_MAGIC\n");
        goto cleanup;
    }

    /* Main handling loop */
    while (true) {
        /* Read opcode from client */
        uint32_t op;
        if (!cmd_read_request_header(state->asockfd, &op)) {
            break;
        }

        /* Handle opcode */
        if (!server_handle_op(state, op)) {
            break;
        }
    }

cleanup:
    printf("Cleaning up server worker\n");
    close(state->asockfd);
    free(state);
    return NULL;
}

void *
server_thread(void *arg)
{
    int sockfd = -1;
    uint16_t port = (uint16_t)(size_t)arg;

    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Failed to create TCP socket");
        goto cleanup;
    }

    /* Bind socket to ip:port */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to bind socket");
        goto cleanup;
    }

    /* Puts socket into listen mode with max 256 pending connections */
    if (listen(sockfd, 256) < 0) {
        perror("Failed to mark socket as listener");
        goto cleanup;
    }

    while (true) {
        /* Wait for client to connect */
        struct sockaddr_in caddr = {0};
        socklen_t caddr_len = sizeof(caddr);
        int asockfd = accept(sockfd, (struct sockaddr *)&caddr, &caddr_len);
        if (asockfd < 0) {
            /* Ignore error, continue */
            perror("Failed to accept client connection");
            continue;
        }

        /* Connection successful! */
        printf("Got connection from %s:%d\n", inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));

        /* Initialize worker thread args */
        server_state_t *arg = malloc(sizeof(server_state_t));
        arg->asockfd = asockfd;
        arg->client_ip = ntohl(caddr.sin_addr.s_addr);

        /* Create worker thread */
        pthread_t thread;
        if (pthread_create(&thread, NULL, server_worker, arg) < 0) {
            perror("Failed to create server worker thread");
            free(arg);
            continue;
        }

        /* Detach worker thread */
        if (pthread_detach(thread) < 0) {
            perror("Failed to detach server worker thread");
            continue;
        }
    }

cleanup:
    printf("Cleaning up server thread\n");
    if (sockfd >= 0) {
        close(sockfd);
    }
    return NULL;
}

int
server_run(uint16_t port)
{
    pthread_t thread;
    void *arg = (void *)(size_t)port;

    if (pthread_create(&thread, NULL, server_thread, arg) < 0) {
        perror("Failed to create server thread");
        return 1;
    }

    pthread_join(thread, NULL);
    return 0;

    if (pthread_detach(thread) < 0) {
        perror("Failed to detach server thread");
        return 1;
    }

    return 0;
}
