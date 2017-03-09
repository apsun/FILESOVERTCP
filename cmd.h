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
 * Magic number denoting a command response.
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
 * File was not found (invalid GUID or peer doesn't have it).
 */
#define CMD_ERR_FILE_NOT_FOUND 0x00000001

/**
 * Block was not found (invalid index or peer doesn't have it).
 */
#define CMD_ERR_BLOCK_NOT_FOUND 0x00000002

/**
 * Command to get file metadata.
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
#define CMD_OP_GET_FILE_META 0x00000001

/**
 * Command to get the server's peer list.
 *
 * Request:
 *   Bytes 0~7: Request header
 *   Bytes 8~23: GUID of the file
 *
 * Response:
 *   Bytes 0~11: Response header
 *   IF (CMD_ERR_OK)
 *     Bytes 12~15: Number of peers
 *     Bytes 16~19: IPv4 address of peer #0
 *     Bytes 20~23: IPv4 address of peer #1
 *     Bytes 24~?: ... and so on
 #   ENDIF
 */
#define CMD_OP_GET_PEER_LIST 0x00000002

/**
 * Command to get the server's block info.
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
#define CMD_OP_GET_BLOCK_LIST 0x00000003

/**
 * Command to get the contents of a block.
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
#define CMD_OP_GET_BLOCK_DATA 0x00000004
