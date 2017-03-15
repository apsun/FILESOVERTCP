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
    file_id_t id = state->meta.id;
    if (!cmd_write(fd, &state->meta.id, sizeof(state->meta.id))) {
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
    file_id_t id = state->meta.id;
    if (!cmd_write(fd, &state->meta.id, sizeof(state->meta.id))) {
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
