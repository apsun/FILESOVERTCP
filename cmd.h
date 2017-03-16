#ifndef CMD_H
#define CMD_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Magic bytes denoting a command request.
 * ASCII for 'RQST'.
 *
 * All requests start with the following header:
 *   Bytes 0~3: CMD_REQUEST
 *   Bytes 4~7: CMD_OP_*
 */
#define CMD_REQUEST 0x54535152

/**
 * Magic bytes denoting a command response.
 * ASCII for 'RESP'.
 *
 * All responses start with the following header:
 *   Bytes 0~3: CMD_RESPONSE
 *   Bytes 4~7: CMD_OP_*
 *   Bytes 8~11: CMD_ERR_*
 */
#define CMD_RESPONSE 0x50534552

/**
 * Operation was successful.
 */
#define CMD_ERR_OK 0x00000000

/**
 * Generic error occurred.
 */
#define CMD_ERR_UNKNOWN 0x80000000

/**
 * Request was malformed.
 */
#define CMD_ERR_MALFORMED 0x80000001

/**
 * File was not found (invalid GUID or peer doesn't have it).
 */
#define CMD_ERR_FILE_NOT_FOUND 0x80000002

/**
 * Block was not found (invalid index or peer doesn't have it).
 */
#define CMD_ERR_BLOCK_NOT_FOUND 0x80000003

/**
 * Command to get file metadata.
 * ASCII for 'META'.
 *
 * Request:
 *   Bytes 0~7: Request header
 *   Bytes 8~11: Length of file name
 *   Bytes 12~?: File name (including NUL terminator)
 *
 * Response:
 *   Bytes 0~11: Response header
 *   IF (CMD_ERR_OK)
 *     Bytes 12~?: file_meta_t struct
 *   ENDIF
 */
#define CMD_OP_GET_FILE_META 0x4154454d

/**
 * Command to get the server's peer list.
 * ASCII for 'PEER'.
 *
 * Request:
 *   Bytes 0~7: Request header
 *   Bytes 8~23: GUID of the file
 *   Bytes 24~25: Local server port
 *
 * Response:
 *   Bytes 0~11: Response header
 *   IF (CMD_ERR_OK)
 *     Bytes 12~15: Number of peers
 *     Bytes 16~19: IPv4 address of peer #0
 *     Bytes 20~21: Server port of peer #0
 *     Bytes 22~25: IPv4 address of peer #1
 *     Bytes 26~27: Server port of peer #1
 *     Bytes 24~?: ... and so on
 *   ENDIF
 */
#define CMD_OP_GET_PEER_LIST 0x52454550

/**
 * Command to get the server's block info.
 * ASCII for 'BLKS'.
 *
 * Request:
 *   Bytes 0~7: Request header
 *   Bytes 8~23: GUID of the file
 *
 * Response:
 *   Bytes 0~11: Response header
 *   IF (CMD_ERR_OK)
 *     Bytes 12~15: Length of the block bitmap, in BITS
 *     Bytes 16~?: Block bitmap. Last byte has extra high bits padded with 0s.
 *   ENDIF
 */
#define CMD_OP_GET_BLOCK_LIST 0x534b4c42

/**
 * Command to get the contents of a block.
 * ASCII for 'DATA'.
 *
 * Request:
 *   Bytes 0~7: Request header
 *   Bytes 8~23: GUID of the file
 *   Bytes 24~31: Block index
 *
 * Response:
 *   Bytes 0~11: Response header
 *   IF (CMD_ERR_OK)
 *     Bytes 12~19: Number of bytes in the block (for verification purposes)
 *     Bytes 20~?: Block bytes
 *   ENDIF
 */
#define CMD_OP_GET_BLOCK_DATA 0x41544144

/**
 * Convenience wrapper for send_all().
 */
bool
cmd_write(int fd, const void *buf, size_t count);

/**
 * Convenience wrapper for recv_all().
 */
bool
cmd_read(int fd, void *buf, size_t count);

/**
 * Writes a request header to the specified file.
 */
bool
cmd_write_request_header(int fd, uint32_t op);

/**
 * Reads a request header from the specified file.
 */
bool
cmd_read_request_header(int fd, uint32_t *op);

/**
 * Writes a response header to the specified file.
 */
bool
cmd_write_response_header(int fd, uint32_t op, uint32_t err);

/**
 * Reads a response header from the specified file.
 */
bool
cmd_read_response_header(int fd, uint32_t *op, uint32_t *err);

#endif
