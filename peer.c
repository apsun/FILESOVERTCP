#include "peer.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

uint32_t
get_peer_list(file_state_t *file, peer_info_t peer_list[MAX_NUM_PEERS])
{
    pthread_mutex_lock(&file->lock);
    uint32_t num_peers = file->num_peers;
    memcpy(peer_list, file->peer_list, num_peers * sizeof(peer_info_t));
    pthread_mutex_unlock(&file->lock);
    return num_peers;
}

bool
peer_remove(file_state_t *file, peer_info_t peer)
{
    pthread_mutex_lock(&(file->lock));
    bool foundpeer = true;
    size_t i;
    for(i = 0; i < file->num_peers; i++)
    {
        peer_info_t temp = file->peer_list[i];
        if((temp.ip_addr == peer.ip_addr) &&(temp.port == peer.port))
        {
            foundpeer = true;            
            break;
        }
    }
    if(foundpeer)
    {
        memmove(file->peer_list + i, file->peer_list + i + 1, (MAX_NUM_PEERS - i - 1) * sizeof(peer_info_t)); //VERIFY THIS WORKS.
    }
    pthread_mutex_unlock(&(file->lock));
    return foundpeer;
}

bool
peer_add(file_state_t * file, peer_info_t peer)
{
    pthread_mutex_lock(&(file->lock));
    bool newpeer = true;
    for(size_t i = 0; i < file->num_peers; i++)
    {
        peer_info_t temp = file->peer_list[i];
        if((temp.ip_addr == peer.ip_addr) &&(temp.port == peer.port))
        {
            newpeer = false;
            break;
        }
    }
    if(newpeer)
    {
        file->peer_list[file->num_peers] = peer;
    }
    pthread_mutex_unlock(&(file->lock));
    return newpeer;
}
