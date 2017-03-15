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
                free(statepeer);
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

bool
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

    /* Write and check the magic bytes */
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

    if (magic != FTCP_MAGIC) {
        printe("Magic mismatch, expected FTCP_MAGIC, got 0x%08x\n", magic);
        return false;
    }

    state->sockfd = sockfd;
    return true;
}


void *
client_worker_new_file(void *arg)
{
    client_state_t *state = arg;
    if (!client_connect(state)) {
        goto cleanup;
    }

    /* Write request header */
    uint32_t op = CMD_OP_GET_FILE_META;
    if (!cmd_write_request_header(fd, op)) {
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
    uint32_t op_resp, err;
    if (!cmd_read_response_header(fd, &op_resp, &err)) {
        printe("Failed to read response header\n");
        goto cleanup;
    }

    /* Check valid op response */
    if (op_resp != CMD_OP_GET_FILE_META) {
        printe("Op mismatch! Expected GET_FILE_META, got: %08x\n", op_resp);
        goto cleanup;
    }

    /* Check error code */
    if (err != CMD_ERR_OK) {
        printe("Server returned error code: %08x\n", err);
        goto cleanup;
    }

    /* Read the metadata */
    file_meta_t meta;
    if (!cmd_read(fd, &meta, sizeof(meta))) {
        printe("Failed to read file metadata\n");
        goto cleanup;
    }

    /* TODO: Write file to disk */
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

void *
client_worker(void *arg)
{
    client_state_t *state = arg;
    if (!client_connect(state)) {
        goto cleanup;
    }

    /* Enter client loop */
    client_loop(state);

cleanup:
    if (state->sockfd >= 0) {
        close(state->sockfd);
    }
    free(state);
    return NULL;
}

static char *
client_get_block_list(client_state_t *state)
{
    int fd = state->sockfd;
    file_state_t *file = state->u.file;

    /* Write request header */
    if (!cmd_write_request_header(fd, CMD_OP_GET_BLOCK_LIST)) {
        return NULL;
    }

    /* Write file ID */
    file_id_t id = state->file->meta.id;
    if (!cmd_write(fd, &state->file->meta.id, sizeof(state->file->meta.id))) {
        return false;
    }

    // get op and err of the response.
    uint32_t op;
    uint32_t err;
    if(!cmd_read_response_header(fd, &op, &err))
    {
        return NULL;
    }

    //check if op and err of the response is correct
    if(op != CMD_OP_GET_BLOCK_LIST || err != CMD_ERR_OK)
    {
        return NULL;
    }

    //get the size of the bitmap
    uint32_t bitmap_size;
    if (!cmd_read(fd, &bitmap_size, sizeof(bitmap_size))) {
        return NULL;
    }

    //get the bitmap
    char * bitmap = malloc(bitmap_size);
    if (!cmd_read(fd, bitmap, (bitmap_size + 7) / 8)) {
        free(bitmap);
        return NULL;
    }

    return bitmap;
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
    char *block_data = malloc(block_size);
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
    char *block_list = NULL;
    while (1) {
        client_get_peer_list(state);
        block_list = client_get_block_list(state);
        if (block_list == NULL) {
            return false;
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

 cleanup:
    free(block_list);
    return true;
}


void *
client_run(void * arg)
{
    //this function should take stdin of filename, ip and port and try and download that file by creating worker threads with those args
    //and then call client_connect.

    char *line = NULL;
    size_t size = 0;
    size_t MAX_THREADS = 4096; //this is just temporary solution
    size_t current_tid = 0;
    pthread_t tid[MAX_THREADS];

    while(getline(&line, &size, stdin) != -1){
        char *temp = strstr(line, "\n");
        if(temp) *temp = '\0';
        char *token = strtok(line, " ");
        char *filename = NULL;
        char *ip = NULL;
        char *port = NULL;
        for(int i = 0; i < 3; i++){
            switch(i){
                case 0:
                    filename = strdup(token);
                    break;
                case 1:
                    ip = strdup(token);
                    break;
                case 2:
                    port = strdup(token); 
                    break;
            }

            token = strtok(NULL, " ");
            if(token == NULL) break;
        }
        
        /**
         *  Create the thread corresponding to the input
         */
        client_state_t *state = malloc(sizeof(client_state_t));

        //set everything except sock fd which is set in client_connect
        state->server_ip = atoi(ip);
        state->server_port = atoi(port);
        strcpy(state->filename,filename);
        state->file_name_len = strlen(filename);
        state->file_index = -1;

        free(filename);
        free(ip);
        free(port);

        pthread_t connection_thread;
        pthread_create(&connection_thread, NULL, &client_connect, state);
        pthread_join(connection_thread, 0);

        pthread_create(&tid[current_tid], NULL, &client_worker, state);
        current_tid++;
    }

    free(line);

    for(size_t i = 0 ; i<current_tid; i++){
      pthread_join(tid[i], 0);
    }


    /* OLD CODE
    pthread_t thread;
    client_state_t *state = malloc(sizeof(client_state_t));
    state->server_ip = 0x7f000001;
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
    */

    return 0;
}
