#define _GNU_SOURCE
#include "server.h"
#include "client.h"
#include "util.h"
#include "type.h"
#include "file.h"
#include "config.h"
#include "peer.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <getopt.h>

static int
usage(const char *name)
{
    printe("usage: %s <options>\n", name);
    printe(" -c <path> -- config file path\n");
    return 1;
}

static int
print_command_instruction(){
    printf("Please enter one of the following commands:\n");
    printf("\n[1] download <filename> -- to download a file"
        "\n[2] upload <path/to/filename> -- to upload a file"
        "\n[3] status <filename> -- to see the status of an uploaded file"
        "\n[4] help -- to learn more about the program"
        "\n[5] exit -- to exit the program \n\n");
    return 1;
}

int
main(int argc, char **argv)
{
    char *config_file = NULL;
    if (argc != 1) {
        int opt = getopt(argc, argv, "c:");
        if(opt == 'c' && argc == 3){
          config_file = strdup(optarg);
        }else return usage(argv[0]);
    }

    load_config(config_file);
    initialize();
    server_run(8888);
    int files = get_num_files();
    for(int i = 0; i < files; i++)
    {
        file_state_t * filetemp;
        if(get_file_by_index(i, &filetemp))
        {
            remove_downloading_blocks(filetemp);
            peer_info_t peer_list[MAX_NUM_PEERS];
            uint32_t numpeers = get_peer_list(filetemp, peer_list);
            for(uint32_t j = 0; j < numpeers; j++)
            {
                client_resume(peer_list[j] , 8889, filetemp);
            }
        }
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    system("clear");
    print_green();
    printf("/**********************\\\n");
    printf("    Welcome to FTCP\n");
    printf("\\**********************/\n\n");
    print_white();
    print_command_instruction();

    while (true) {

        //Reads the user's option

        printf("FTCP> ");
        if ((read = getline(&line, &len, stdin)) < 0) {
            break;
        }

        printf("\n");

        char *cmd = trim_string(line);
        if (starts_with(cmd, "download ")) {
            char *fname = cmd + strlen("download ");
            fname = trim_string(fname);
            char *address = NULL;
            printf("What is the address? ");
            if ((read = getline(&address, &len, stdin)) < 0) {
                break;
            }
            printf("What is the port? ");
            if ((read = getline(&line, &len, stdin)) < 0) {
                break;
            }
            client_start(address, atoi(line), 8889, fname);
            flush();
        } else if (starts_with(cmd, "upload ")) {
            char *path = cmd + strlen("upload ");
            path = trim_string(path);
            file_state_t *f;
            add_local_file(path, &f);
            flush();
        } else if (starts_with(cmd, "status ")) {
            char *fname = cmd + strlen("status ");
            fname = trim_string(fname);
            file_state_t *f;
            if (!get_file_by_name(fname, &f)) {
                printf("Unknown file\n");
            } else {
                printf("File name: %s\n", f->meta.file_name);
                printf("File size: %ld\n", f->meta.file_size);
                printf("Number of peers: %d\n", f->num_peers);

                uint32_t downloaded = 0;
                uint32_t downloading = 0;
                for(uint32_t i = 0; i<f->meta.block_count; i++){
                    if(f->block_status[i] == BS_HAVE) downloaded++; 
                    else if(f->block_status[i] == BS_DOWNLOADING) downloading++; 
                }
                double frac_downloaded = downloaded/(double)f->meta.block_count;
                double frac_downloading = downloading/(double)f->meta.block_count;
                uint32_t bar_size = 40;
                uint32_t bar_downloaded = (uint32_t)(frac_downloaded * bar_size);
                uint32_t bar_downloading = (uint32_t)(frac_downloading * bar_size);
                printf("/");
                for(uint32_t i = 0; i<bar_size; i++){
                  printf("-"); 
                }
                printf("\\\n");

                printf("|");
                for(uint32_t i = 0; i<bar_size; i++){
                  if(i < bar_downloaded){
                    print_green();
                    printf("*");
                    print_white();
                  }else if(i < bar_downloaded + bar_downloading){
                    print_red();
                    printf("*");
                    print_white();
                  }else printf(" ");
                }
                printf("|\n");
                
                printf("\\");
                for(uint32_t i = 0; i<bar_size; i++){
                  printf("-"); 
                }
                printf("/\n");

                print_green();
                printf("\ndownloaded: %f%%\n", 100*frac_downloaded);
                print_red();
                printf("downloading: %f%%\n\n", 100*frac_downloading);
                print_white();
            }
        } else if (strcmp(cmd, "exit") == 0) {
            break;
        } else if (strcmp(cmd, "help") == 0) {
            print_green();
            printf("FTCP 1.0\n"
                  "This program is created to speed up the process of transferring files. As there are more people downloading the same file, the speed will significantly increase, similarly to Torrent. Unlike Torrent, however, we do not require trackers but just regular users. This allows for greater flexibility and ease of use.\n\n");
            print_white();
            print_command_instruction();
        }else {
            print_red();
            printf("INVALID COMMAND!\n");
            print_white();
            print_command_instruction();
        }
    }

    flush();
    finalize();
    printf("Bye!\n");
    free(line);
    if(config_file) free(config_file);
    return 0;
}
