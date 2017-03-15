
static bool
client_get_peer_list(client_state_t *state)
{
    int fd = state->sockfd;
    file_state_t *file = state->u.file;

    /* Write request header */
    if (!cmd_write_request_header(fd, CMD_OP_GET_PEER_LIST)) {
        return false;
    }

    /* Write file ID */
    file_id_t id = state->meta.id;
    if (!cmd_write(fd, &state->meta.id, sizeof(state->meta.id))) {
        return false;
    }

    /* Get response */
    uint32_t op, err;
    if (!cmd_read_response_header(fd, &op, &err)) {
        return false;
    }

    /* Check response op and error code */
    if (op != CMD_OP_GET_PEER_LIST || err != CMD_ERR_OK) {
        return false;
    }

    /* Read number of peers */
    uint32_t num_peers;
    if (!cmd_read(fd, &num_peers, sizeof(num_peers))) {
        return false;
    }

    /* Read each peer */
    for (uint32_t i = 0; i < num_peers; ++i) {
        peer_info_t peer;

        /* Read peer IP */
        if (!cmd_read(fd, &peer.ip_addr, sizeof(peer.ip_addr))) {
            return false;
        }

        /* Read peer port */
        if (!cmd_read(fd, &peer.port, sizeof(peer.port))) {
            return false;
        }

        /* If we haven't seen this peer before, connect to it */
        /* TODO: This should go into a queue in the future */
        if (add_new_peer(file, peer)) {
            client_state_t *new_arg = malloc(sizeof(client_state_t));
            new_arg->server = server;
            new_arg->u.file = file;

            /* Spawn new thread for peer */
            pthread_t thread;
            if (pthread_create(&thread, NULL, client_worker, new_arg) < 0) {
                perror("Failed to create new worker thread");
                free(statepeer);
                return false;
            }

            /* Try to detach new thread */
            if (pthread_detach(thread) < 0) {
                perror("Failed to detach worker thread");
                /* Ignore, not a big deal (I think) */
            }
        }
    }

    return true;
}


bool
client_connect(client_state_t *state)
{
    int sockfd = -1;

    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Failed to create TCP socket");
        return false;
    }

    /* Connect to server */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(state->server_port);
    addr.sin_addr.s_addr = htonl(state->server_ip);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to connect to server");
        close(sockfd);
        return false;
    }

    /* Connection successful! */
    printf("Connected to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    /* Write and check the magic bytes */
    uint32_t magic = FTCP_MAGIC;
    if (!cmd_write(fd, &magic, sizeof(magic))) {
        printe("Failed to write FTCP_MAGIC\n");
        close(sockfd);
        return false;
    }

    /* Read magic from server */
    if (!cmd_read(fd, &magic, sizeof(magic))) {
        printe("Failed to read FTCP_MAGIC\n");
        close(sockfd);
        return false;
    }

    if (magic != FTCP_MAGIC) {
        printe("Magic mismatch, expected FTCP_MAGIC, got 0x%08x\n", magic);
        return false;
    }

    state->sockfd = sockfd;
    return true;
}


void *
client_worker_new_file(void *arg)
{
    client_state_t *state = arg;
    if (!client_connect(state)) {
        goto cleanup;
    }

    /* Write request header */
    uint32_t op = CMD_OP_GET_FILE_META;
    if (!cmd_write_request_header(fd, op)) {
        printe("Failed to write request header\n");
        goto cleanup;
    }

    /* Note the +1; the spec accounts for the NUL char */
    char *str = file->u.file_name;
    uint32_t len = strlen(str) + 1;

    /* Write string length */
    if (!cmd_write(fd, &len, sizeof(len))) {
        printe("Failed to write string length\n");
        goto cleanup;
    }

    /* Write string contents */
    if (!cmd_write(fd, str, len)) {
        printe("Failed to write string\n");
        goto cleanup;
    }

    /* Read response header */
    uint32_t op_resp, err;
    if (!cmd_read_response_header(fd, &op_resp, &err)) {
        printe("Failed to read response header\n");
        goto cleanup;
    }

    /* Check valid op response */
    if (op_resp != CMD_OP_GET_FILE_META) {
        printe("Op mismatch! Expected GET_FILE_META, got: %08x\n", op_resp);
        goto cleanup;
    }

    /* Check error code */
    if (err != CMD_ERR_OK) {
        printe("Server returned error code: %08x\n", err);
        goto cleanup;
    }

    /* Read the metadata */
    file_meta_t meta;
    if (!cmd_read(fd, &meta, sizeof(meta))) {
        printe("Failed to read file metadata\n");
        goto cleanup;
    }

    /* TODO: Write file to disk */
    file_state_t *file = create_local_file(&meta);

    /* Enter client loop */
    state->u.file = file;
    client_loop(state);

 cleanup:
    if (state->sockfd >= 0) {
        close(state->sockfd);
    }
    free(state);
    return NULL;
}

void *
client_worker(void *arg)
{
    client_state_t *state = arg;
    if (!client_connect(state)) {
        goto cleanup;
    }

    /* Enter client loop */
    client_loop(state);

cleanup:
    if (state->sockfd >= 0) {
        close(state->sockfd);
    }
    free(state);
    return NULL;
}
