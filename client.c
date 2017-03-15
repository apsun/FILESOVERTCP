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

extern pthread_mutex_t lock;
extern char blocklist[MAX_NUM_FILES][MAX_NUM_BLOCKS];
extern file_meta_t filelist[MAX_NUM_FILES];
extern int files;
extern int fdList[MAX_NUM_FILES];
extern peer_t peerlist[MAX_NUM_FILES][MAX_NUM_PEERS];
extern int peer_per_file[MAX_NUM_FILES];

typedef struct {
    uint32_t server_ip;
    uint16_t server_port;
    int sockfd;
    char filename[256];
    int file_name_len;
    //file_meta_t meta; 
    //maybe we store the GUID since every command needs it.
    int file_index;
} client_state_t;



static char *
client_handle_get_block_list(client_state_t *state)
{
    int fd = state->sockfd;

    //send request header
    if(!cmd_write_request_header(fd, CMD_OP_GET_BLOCK_LIST))
    {
        return NULL;
    }

    //send guid
    pthread_mutex_lock(&lock);
    file_id_t id = filelist[state->file_index].id;
    pthread_mutex_unlock(&lock);
    if (!cmd_write(fd, &id, sizeof(id))) 
    {
        return NULL;
    }

    //get op and err of the response.
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
    if (!cmd_read(fd, bitmap, bitmap_size)){
        free(bitmap);
        return NULL;
    }
    return bitmap;
}

static bool
client_handle_get_block_data(client_state_t *state, uint32_t block_index)
{
    int fd = state->sockfd;

    //send request header
    if(!cmd_write_request_header(fd, CMD_OP_GET_BLOCK_DATA))
    {
        return false;
    }

    //send guid
    pthread_mutex_lock(&lock);
    file_id_t id = filelist[state->file_index].id;
    pthread_mutex_unlock(&lock);
    if (!cmd_write(fd, &id, sizeof(id))) 
    {
        return false;
    }

    //send block index.
    if (!cmd_write(fd, &block_index, sizeof(block_index))) 
    {
        return false;
    }

    //get op and err of the response.
    uint32_t op;
    uint32_t err;
    if(!cmd_read_response_header(fd, &op, &err))
    {
        return false;
    }

    //check if op and err of the response is correct
    if(op != CMD_OP_GET_BLOCK_DATA || err != CMD_ERR_OK)
    {
        return false;
    }

    //get the size of the block
    uint32_t block_size;
    if (!cmd_read(fd, &block_size, sizeof(block_size))) {
        return false;
    }
    //get the block
    char * blockdata = malloc(block_size);
    if (!cmd_read(fd, blockdata, block_size)){
        free(blockdata);
        return false;
    }
    //write the block.
    pthread_mutex_lock(&lock);
    int filefd = fdList[state->file_index];
    pthread_mutex_unlock(&lock);
    off_t offset = block_index * block_size;
    if(!write_block(filefd, blockdata, block_size, offset))
    {
        free(blockdata);
        return false;
    }
    //set the block as have
    pthread_mutex_lock(&lock);
    blocklist[state->file_index][block_index] = 2;
    pthread_mutex_unlock(&lock);
    return true;
}

static bool
client_get_blocks(client_state_t *state)
{
    //this function will get the connections block check it against our blocks see if their is anything to get and mark it as downloading and get it.
    //repeat this process till their is no blocks left then maybe restart it.
    return true;
}

static bool
client_handle_get_peer_list(client_state_t *state)
{
    int fd = state->sockfd;

    //send request header
    if(!cmd_write_request_header(fd, CMD_OP_GET_PEER_LIST))
    {
        return false;
    }

    //send guid
    pthread_mutex_lock(&lock);
    file_id_t id = filelist[state->file_index].id;
    pthread_mutex_unlock(&lock);
    if (!cmd_write(fd, &id, sizeof(id))) 
    {
        return false;
    }

    //get op and err of the response.
    uint32_t op;
    uint32_t err;
    if(!cmd_read_response_header(fd, &op, &err))
    {
        return false;
    }

    //check if op and err of the response is correct
    if(op != CMD_OP_GET_PEER_LIST || err != CMD_ERR_OK)
    {
        return false;
    }

    //get the num of peers
    uint32_t num_peers;
    if (!cmd_read(fd, &num_peers, sizeof(num_peers))) {
        return false;
    }
    //get all of the peer information
    peer_t * peers = malloc(num_peers * sizeof(peer_t));
    for (uint32_t i = 0; i < num_peers; ++i) {
        if (!cmd_read(fd, &(peers[i].ip_addr), sizeof(peers[i].ip_addr))) {
            free(peers);
            return false;
        }
        if (!cmd_read(fd, &(peers[i].port), sizeof(peers[i].port))) {
            free(peers);
            return false;
        }
    }
    // and if they are new writing them to your peerlist and making a thread to connect to them,
    pthread_mutex_lock(&lock);
    int oldpeers = peer_per_file[state->file_index]; //sicne we assume that the new peers we got have no duplicates.
    for(size_t i = 0; i < num_peers; i++)
    {
        bool newpeer = true;
        for(int j = 0; j < oldpeers; j++)
        {
            peer_t temp = peerlist[state->file_index][j];
            if((temp.ip_addr == peers[i].ip_addr) &&(temp.port == peers[i].port))
            {
                newpeer = false;
                break;
            }
        }
        if(newpeer)//we need to now connect to this newpeer and add it to out peerlist.
        {
            client_state_t *statepeer = malloc(sizeof(client_state_t));
            statepeer->server_ip = peers[i].ip_addr;
            statepeer->server_port = peers[i].port;
            statepeer->file_index = state->file_index;
            //we do not need to set filename and fielname len since you will not be calling get file meta since we already have the meta.
            pthread_t thread;
            if (pthread_create(&thread, NULL, client_connect, (void *)statepeer) < 0) {
                perror("Failed to create peers thread");
                free(statepeer);
            }
            else
            {
                peerlist[state->file_index][peer_per_file[state->file_index]] = peers[i];
                peer_per_file[state->file_index]++;
            }
            //do we have to detach the thread? no idea.
        }
    }
    pthread_mutex_unlock(&lock); //this locked section might be too long and cause stalls elsewhere.
    return client_get_blocks(state); //after we get the peers we need to get the blocks that we can.
}

static bool
client_handle_get_file_meta(client_state_t *state)
{
    int fd = state->sockfd;
    //send request header
    if(!cmd_write_request_header(fd, CMD_OP_GET_FILE_META))
    {
        return false;
    }
    //send file name length
    if (!cmd_write(fd, &state->file_name_len, sizeof(state->file_name_len))) 
    {
        return false;
    }
    //send file name
    if (!cmd_write(fd, state->filename, state->file_name_len)) 
    {
        return false;
    }

    //get op and err of the response.
    uint32_t op;
    uint32_t err;
    if(!cmd_read_response_header(fd, &op, &err))
    {
        return false;
    }

    //check if op and err of the response is correct
    if(op != CMD_OP_GET_FILE_META || err != CMD_ERR_OK)
    {
        return false;
    }
    //get the actual meta.
    file_meta_t meta;
    if (!cmd_read(fd, &meta, sizeof(meta))) {
        return false;
    }
    //store the meta annd open fd for file and store that.
    pthread_mutex_lock(&lock);
    int tempfd = open( state->filename, O_CREAT | O_RDWR ); //should prolly put the file in the directory
    if(tempfd == -1)
    {
        pthread_mutex_unlock(&lock);
        return false;
    }
    filelist[files] = meta;
    fdList[files] = tempfd;
    state->file_index = files;
    files++;
    pthread_mutex_unlock(&lock);
    return true; //after we get the file meta we just get the peerlist in client connect now.
}

void *
client_connect(void * args)
{
    int sockfd = -1;
    client_state_t  * state = (client_state_t *) args;
    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Failed to create TCP socket");
        return NULL;
    }

    /* Connect to server */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(state->server_port);
    addr.sin_addr.s_addr = htonl(state->server_ip);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to connect to server");
        close(sockfd);
        return NULL;
    }

    /* Connection successful! */
    printf("Connected to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    state->sockfd = sockfd;
    if(state->file_index == -1) //we dont have the file meta.
    {
        client_handle_get_file_meta(state);
    }
    client_handle_get_peer_list(state); //get peer list after we have files or if we already did.
    //i guess its fine if this function always returns null?
    return NULL;
}

void *
client_worker(void *arg)
{
    //this function should be removed since each new connection starts at client connect.
    client_state_t *state = arg;

    /* Connect to the server */
    if (!client_connect((void *)state)) {
        goto cleanup;
    }
    int fd = state->sockfd;

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
    //this function should take stdin of filename, ip and port and try and download that file by creating worker threads with those args
    //and then call client_connect.
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
