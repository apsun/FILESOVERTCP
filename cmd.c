#include "cmd.h"
#include "util.h"
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

static bool
is_valid_op(uint32_t op)
{
    switch (op) {
    case CMD_OP_GET_FILE_META:
    case CMD_OP_GET_PEER_LIST:
    case CMD_OP_GET_BLOCK_LIST:
    case CMD_OP_GET_BLOCK_DATA:
        return true;
    default:
        return false;
    }
}

static bool
is_valid_err(uint32_t err)
{
    switch (err) {
    case CMD_ERR_OK:
    case CMD_ERR_UNKNOWN:
    case CMD_ERR_MALFORMED:
    case CMD_ERR_FILE_NOT_FOUND:
    case CMD_ERR_BLOCK_NOT_FOUND:
        return true;
    default:
        return false;
    }
}

bool
cmd_write(int fd, const void *buf, size_t count)
{
    return write_all(fd, buf, count);
}

bool
cmd_read(int fd, void *buf, size_t count)
{
    return read_all(fd, buf, count);
}

bool
cmd_write_request_header(int fd, uint32_t op)
{
    uint32_t buf[2] = {CMD_REQUEST, op};
    return write_all(fd, buf, sizeof(buf));
}

bool
cmd_read_request_header(int fd, uint32_t *op)
{
    uint32_t buf[2];

    /* Read data */
    if (!read_all(fd, buf, sizeof(buf))) {
        return false;
    }

    uint32_t magic = buf[0];
    uint32_t op_tmp = buf[1];

    /* Check request magic */
    if (magic != CMD_REQUEST) {
        printe("Expected CMD_REQUEST, got 0x%08x\n", magic);
        return false;
    }

    /* Check opcode */
    if (!is_valid_op(op_tmp)) {
        printe("Expected CMD_OP_*, got 0x%08x\n", op);
        return false;
    }

    /* Write data */
    *op = op_tmp;
    return true;
}

bool
cmd_write_response_header(int fd, uint32_t op, uint32_t err)
{
    uint32_t buf[3] = {CMD_RESPONSE, op, err};
    return write_all(fd, buf, sizeof(buf));
}

bool
cmd_read_response_header(int fd, uint32_t *op, uint32_t *err)
{
    uint32_t buf[3];

    /* Read data */
    if (!read_all(fd, buf, sizeof(buf))) {
        return false;
    }

    uint32_t magic = buf[0];
    uint32_t op_tmp = buf[1];
    uint32_t err_tmp = buf[2];

    /* Check response magic */
    if (magic != CMD_RESPONSE) {
        printe("Expected CMD_RESPONSE, got 0x%08x\n", magic)
        return false;
    }

    /* Check opcode */
    if (!is_valid_op(op_tmp)) {
        printe("Expected CMD_OP_*, got 0x%08x\n", op);
        return false;
    }

    /* Check error code */
    if (!is_valid_err(err_tmp)) {
        printe("Expected CMD_ERR_*, got 0x%08x\n", err);
        return false;
    }

    /* Write data */
    *op = op_tmp;
    *err = err_tmp;
    return true;
}