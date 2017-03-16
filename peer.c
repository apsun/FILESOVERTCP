#include "peer.h"
#include "util.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static bool
peer_equals(peer_info_t *a, peer_info_t *b)
{
    return a->ip_addr == b->ip_addr && a->port == b->port;
}

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
peer_add(file_state_t *file, peer_info_t peer)
{
    pthread_mutex_lock(&file->lock);
    for (uint32_t i = 0; i < file->num_peers; ++i) {
        if (peer_equals(&peer, &file->peer_list[i])) {
            debugf("Peer already in list: %08x:%u", peer.ip_addr, peer.port);
            pthread_mutex_unlock(&file->lock);
            return false;
        }
    }

    debugf("Added peer to list: %08x:%u", peer.ip_addr, peer.port);
    file->peer_list[file->num_peers++] = peer;
    pthread_mutex_unlock(&file->lock);
    return true;
}

bool
peer_remove(file_state_t *file, peer_info_t peer)
{
    pthread_mutex_lock(&file->lock);
    bool found = false;
    uint32_t i;
    for (i = 0; i < file->num_peers; ++i) {
        if (peer_equals(&peer, &file->peer_list[i])) {
            found = true;
            break;
        }
    }

    if (found) {
        debugf("Removed peer from list: %08x:%u", peer.ip_addr, peer.port);
        memmove(&file->peer_list[i], &file->peer_list[i + 1], --file->num_peers - i);
    }

    pthread_mutex_unlock(&file->lock);
    return found;
}
