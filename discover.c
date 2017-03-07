#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/*
 * File transfer protocol:
 *
 * Suppose A wants to download a file.
 *
 * A connects to B, who A knows has the complete file. B is the "root peer".
 *
 * B tells A a list of peers (C[1..n]) who have already
 * downloaded some blocks of the file from B.
 * (TODO: How do we prune people from this list? Heartbeat?)
 *
 * A connects to each peer C[1..n] and repeats the previous step.
 * (This is essentially network BFS where each node = peer.)
 * Since this may take a very long time, it's done in the background.
 *
 * Meanwhile, A sends to each peer (call them X) that they have discovered
 * a "block status". A tells X which parts of the file A has, and
 * X also replies with a "block status", which tells A which parts of the
 * file X has. This also adds A to the peer list of X.
 *
 * Now, A sends X a "block request" (and X can also send one to A if they
 * are also downloading). This contains the file offset, block length, etc.
 * X then replies with the contents of the block.
 *
 * Once A has received the whole block, they update their internal block
 * tracker and writes the block to disk. Now, any peers connecting to A
 * (who they know from connecting to X) can also download the block from A.
 */

typedef struct {
    /*
     * Where in the file the block starts, in bytes from offset 0.
     */
    uint64_t file_offset;

    /*
     * The length of the block, in bytes.
     */
    uint64_t block_length;

    /*
     * Block information. Currently unused.
     */
    uint64_t flags;

    /*
     * SHA-3 hash of the block. Used for integrity checks.
     * TODO: Maybe a CRC32 is fine, we'll have to hash the entire
     * file at the end anyways.
     */
    uint64_t hash;
} block_info_t;

typedef struct {
    /*
     * IP address of the peer.
     */
    uint32_t ipv4_addr;

    /*
     * Info about the blocks that this peer currently has.
     */
    block_info_t blocks[];
} peer_info_t;
