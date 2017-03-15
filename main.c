#include "server.h"
#include "client.h"
#include "util.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "type.h"
#include <pthread.h>
#include <dirent.h>
#include "block.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if 0
int num_files;
file_state_t files[MAX_NUM_FILES];


//GLOBAL DECLARATIONS change to pointers.

/**
 * Array holding meta information for all files we have or are getting.
 */
file_meta_t filelist[MAX_NUM_FILES];
/**
 * Array holding meta information of blocks for all files we have or are getting.
 */
char blocklist[MAX_NUM_FILES][MAX_NUM_BLOCKS];
/**
 * Represents how many files we have or are getting.
 */
int files = 0;
/**
 * Array of fd for files we have or are getting.
 */
int fdList[MAX_NUM_FILES];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

peer_t peerlist[MAX_NUM_FILES][MAX_NUM_PEERS];
// i know this array is bad
int peer_per_file[MAX_NUM_FILES];


static int
usage(const char *name) //this function is outdated.
{
    printe("usage: %s <mode>\n", name);
    printe("  mode -- \"client\" or \"server\"\n");
    return 1;
}

int
main(int argc, char **argv)
{
    if (argc != 3) {
        return usage(argv[0]);
    }

    const char *dirName = argv[1];
    int port = atoi(argv[2]);
    struct dirent *entry;
    DIR *dp;

    dp = opendir(dirName);
    if (dp == NULL) {
        printe("Can not open directory");
        return -1;
    }

    while((entry = readdir(dp)))
    {
        char pathname[4096]; //the maximum path length on linux
        sprintf( pathname, "%s/%s", dirName, entry->d_name );
        fdList[files] = open( pathname, O_RDONLY ); //should only need to be read to
        struct stat buf;
        fstat(fdList[files], &buf);
        filelist[files].magic = FTCP_MAGIC;
        filelist[files].file_name_len = strlen(entry->d_name) + 1;
        filelist[files].file_size = buf.st_size;
        filelist[files].block_size = block_calculate_size(filelist[files].file_size);
        filelist[files].block_count = (filelist[files].file_size % filelist[files].block_size) ? (filelist[files].file_size / filelist[files].block_size) + 1 : (filelist[files].file_size / filelist[files].block_size);
        //filelist[files].file_hash = ?
        //filelist[files].id = ?
        for(size_t i = 0; i < filelist[files].file_name_len; i++)
        {
            filelist[files].file_name[i] = entry->d_name[i];
        }
        for(size_t i = 0; i < filelist[files].block_count; i++)
        {
            //filelist[files].block_hashes[i] = ?;
            blocklist[files][i] = 2; //we have everthing
        }
        files++;
    }
    pthread_t thread1;
    pthread_t thread2;
    void *arg = (void *)(size_t)port;

    if (pthread_create(&thread1, NULL, &server_thread, arg) < 0) {
        perror("Failed to create server thread");
        return 1;
    }
    if (pthread_create(&thread2, NULL, &client_run, NULL) < 0) { //need to modify cleint run so it takes stdin for filename, ip, and port
        perror("Failed to create client thread");
        return 1;
    }
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    return 0;
}
#endif

int main()
{
    return 0;
}
