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
    uint32_t server_ip;
    uint16_t server_port;
    int sockfd;
} client_state_t;

static int
client_connect(client_state_t *state)
{
    int sockfd = -1;

    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Failed to create TCP socket");
        return -1;
    }

    /* Connect to server */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(state->server_port);
    addr.sin_addr.s_addr = htonl(state->server_ip);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to connect to server");
        close(sockfd);
        return -1;
    }

    /* Connection successful! */
    printf("Connected to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    return sockfd;
}

void *
client_worker(void *arg)
{
    int fd;
    client_state_t *state = arg;

    /* Connect to the server */
    if ((fd = client_connect(state)) < 0) {
        goto cleanup;
    }

    /* Read and check the magic bytes */
    uint32_t magic = FTCP_MAGIC;
    if (!cmd_write(fd, &magic, sizeof(magic))) {
        printe("Failed to write FTCP_MAGIC\n");
        goto cleanup;
    }

    /* Read magic from server */
    if (!cmd_read(fd, &magic, sizeof(magic))) {
        printe("Failed to read FTCP_MAGIC\n");
        goto cleanup;
    }

    if (magic != FTCP_MAGIC) {
        printe("Magic mismatch, expected FTCP_MAGIC, got 0x%08x\n", magic);
        goto cleanup;
    }

    /*** DEBUGGING CODE ***/
    uint32_t op = CMD_OP_GET_FILE_META;
    if (!cmd_write_request_header(fd, op)) {
        printe("Failed to write request header\n");
        goto cleanup;
    }

    char str[] = "test.txt";
    uint32_t len = sizeof(str);
    if (!cmd_write(fd, &len, sizeof(len))) {
        printe("Failed to write string length\n");
        goto cleanup;
    }

    if (!cmd_write(fd, str, sizeof(str))) {
        printe("Failed to write string\n");
        goto cleanup;
    }

    printf("Sent string!\n");

    uint32_t op_resp, err;
    if (!cmd_read_response_header(fd, &op_resp, &err)) {
        printe("Failed to read response header\n");
        goto cleanup;
    }

    if (op_resp != op) {
        printe("Op mismatch!\n");
        goto cleanup;
    }

    file_meta_t meta;
    if (!cmd_read(fd, &meta, sizeof(meta))) {
        printe("Failed to read file metadata\n");
        goto cleanup;
    }

    printf("Received response!\n");
    /*** END DEBUGGING CODE ***/

cleanup:
    if (fd >= 0) {
        close(fd);
    }
    free(state);
    return NULL;
}

void *
client_run(void * arg)
{
    pthread_t thread;
    client_state_t *state = malloc(sizeof(client_state_t));
    state->server_ip = 0x7f000001; /* 127.0.0.1 */
    state->server_port = 8888;

    if (pthread_create(&thread, NULL, client_worker, state) < 0) {
        perror("Failed to create client thread");
        return 1;
    }

    pthread_join(thread, NULL);
    return 0;

    if (pthread_detach(thread) < 0) {
        perror("Failed to detach client thread");
        return 1;
    }

    return 0;
}
