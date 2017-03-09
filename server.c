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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

typedef struct {
    int asockfd;
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
        cmd_write_response_header(fd, op, CMD_ERR_FILE_NOT_FOUND);
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

    /* TODO: Get file info here */
    file_meta_t meta;

    /* Write response header */
    if (!cmd_write_response_header(fd, op, CMD_ERR_OK)) {
        return false;
    }

    /* Write response */
    if (!cmd_write(fd, &meta, sizeof(meta))) {
        return false;
    }

    return true;
}

static bool
server_handle_get_peer_list(server_state_t *state)
{
    /* TODO */
    return false;
}

static bool
server_handle_get_block_list(server_state_t *state)
{
    /* TODO */
    return false;
}

static bool
server_handle_get_block_data(server_state_t *state)
{
    /* TODO */
    return false;
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

int
server_loop(uint16_t port)
{
    int sockfd = -1;
    int ret = 1;

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

    /* Not sure how we're ever going to reach this... */
    ret = 0;

cleanup:
    if (sockfd >= 0) {
        close(sockfd);
    }
    return ret;
}
