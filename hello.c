#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libgen.h>

typedef struct
{
    /*
     * Size of the file in bytes.
     */
    uint64_t size;

    /*
     * Time of last file modification, in
     * seconds relative to the Unix epoch (UTC).
     */
    uint64_t mod_time;

    /*
     * Length of the filename, including NUL terminator.
     * Will always be <= 4096.
     */
    uint16_t name_len;

    /*
     * Name of the file, including NUL terminator.
     */
    char name[4096];
} file_header_t;

void
printe(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
}

bool
write_all(int fd, const void *buf, size_t count)
{
    const char *bufc = buf;
    size_t total = 0;
    do {
        ssize_t num = write(fd, bufc + total, count - total);
        if (num < 0) {
            perror("Write failed");
            return false;
        }
        total += num;
    } while (total < count);
    return true;
}

bool
read_all(int fd, void *buf, size_t count)
{
    char *bufc = buf;
    size_t total = 0;
    do {
        ssize_t num = read(fd, bufc + total, count - total);
        if (num < 0) {
            perror("Read failed");
            return false;
        }
        total += num;
    } while (total < count);
    return true;
}

bool
copy_string(char *dest, const char *src, size_t *length)
{
    size_t n = *length;
    for (size_t i = 0; i < n; ++i) {
        if ((dest[i] = src[i]) == '\0') {
            *length = i;
            return true;
        }
    }
    return false;
}

bool
get_file_name(char *out_name, const char *path, size_t *length)
{
    char *s = strrchr(path, '/');
    if (s == NULL) {
        return copy_string(out_name, path, length);
    } else {
        return copy_string(out_name, s + 1, length);
    }
}

bool
write_header(int fd, const file_header_t *header)
{
    /* WARNING: Assuming server and client have same endianness */
    bool ok = true;
    ok = ok && write_all(fd, &header->size, sizeof(header->size));
    ok = ok && write_all(fd, &header->mod_time, sizeof(header->mod_time));
    ok = ok && write_all(fd, &header->name_len, sizeof(header->name_len));
    ok = ok && write_all(fd, header->name, header->name_len);
    return ok;
}

bool
read_header(int fd, file_header_t *out_header)
{
    /* WARNING: Assuming server and client have same endianness */
    bool ok = true;
    ok = ok && read_all(fd, &out_header->size, sizeof(out_header->size));
    ok = ok && read_all(fd, &out_header->mod_time, sizeof(out_header->mod_time));
    ok = ok && read_all(fd, &out_header->name_len, sizeof(out_header->name_len));
    ok = ok && read_all(fd, out_header->name, out_header->name_len);
    return ok;
}

bool
init_header(file_header_t *header, int filefd, const char *input_path)
{
    /* Get file attributes */
    struct stat st;
    if (fstat(filefd, &st) < 0) {
        perror("Failed to get file attributes");
        return false;
    }

    header->size = (uint64_t)st.st_size;
    header->mod_time = (uint64_t)st.st_mtime;
    size_t name_len = sizeof(header->name);
    if (!get_file_name(header->name, input_path, &name_len)) {
        printe("Failed to get file name\n");
        return false;
    }
    header->name_len = (uint16_t)name_len;
    return true;
}

bool
copy_streams(int tofd, int fromfd)
{
    char buf[4096];
    ssize_t num;
    while ((num = read(fromfd, buf, sizeof(buf))) > 0) {
        if (!write_all(tofd, buf, num)) {
            return false;
        }
    }
    if (num < 0) {
        perror("Read failed");
        return false;
    }
    return true;
}

int
usage(const char *name)
{
    printe("usage: %s <mode> <ip> <port> <file>\n", name);
    printe("  mode -- \"client\" or \"server\"\n");
    printe("  ip   -- 0.0.0.0 for server, 127.0.0.1 for client\n");
    printe("  port -- 8888\n");
    printe("  file -- stuff.txt");
    return 1;
}

int
run_client(const char *ip, unsigned short port, const char *input_path)
{
    int sockfd = -1;
    int filefd = -1;
    int ret = 1;

    /* Open input file for reading */
    filefd = open(input_path, O_RDONLY);
    if (filefd < 0) {
        perror("Failed to open file");
        goto cleanup;
    }

    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Failed to create TCP socket");
        goto cleanup;
    }

    /* Connect to server */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to connect to server");
        goto cleanup;
    }

    /* Connection successful! */
    printf("Connected to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    /* Initialize file header */
    file_header_t header;
    if (!init_header(&header, filefd, input_path)) {
        printe("Failed to initialize file header\n");
        goto cleanup;
    }
    
    /* Write file header */
    if (!write_header(sockfd, &header)) {
        printe("Failed to write file header\n");
        goto cleanup;
    }

    /* Write file contents */
    if (!copy_streams(sockfd, filefd)) {
        printe("Failed to write file contents\n");
        goto cleanup;
    }

    printf("File sent!\n");

cleanup:
    if (sockfd >= 0) {
        close(sockfd);
    }
    if (filefd >= 0) {
        close(filefd);
    }
    return ret;
}

int
run_server(const char *ip, unsigned short port, const char *output_path)
{
    int sockfd = -1;
    int asockfd = -1;
    int filefd = -1;
    int ret = 1;

    /* Open output file */
    filefd = open(output_path, O_RDWR | O_CREAT, 0644);
    if (filefd < 0) {
        perror("Failed to open output file for writing");
        goto cleanup;
    }

    /* Clear file if it exists */
    if (ftruncate(filefd, 0) < 0) {
        perror("Failed to truncate output file");
        goto cleanup;
    }

    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Failed to create TCP socket");
        goto cleanup;
    }

    /* Bind socket to ip:port */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to bind socket");
        goto cleanup;
    }

    /* Puts socket into listen mode with max 10 pending connections */
    if (listen(sockfd, 10) < 0) {
        perror("Failed to mark socket as listener");
        goto cleanup;
    }

    /* Wait for client to connect */
    struct sockaddr_in caddr = {0};
    socklen_t caddr_len = sizeof(caddr);
    asockfd = accept(sockfd, (struct sockaddr *)&caddr, &caddr_len);
    if (asockfd < 0) {
        perror("Failed to accept client connection");
        goto cleanup;
    }

    /* Connection successful! */
    printf("Got connection from %s:%d\n", inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));

    /* Read file header */
    file_header_t header;
    read_header(asockfd, &header);
    printf("File name: %s\n", header.name);
    printf("File size: %lu\n", header.size);
    printf("Mod time: %lu\n", header.mod_time);

    /* Read file contents */
    if (!copy_streams(filefd, asockfd)) {
        printe("Failed to write output file\n");
        goto cleanup;
    }

    printf("File received!\n");

 cleanup:
    if (asockfd >= 0) {
        close(asockfd);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
    if (filefd >= 0) {
        close(filefd);
    }
    return ret;
}

int
main(int argc, char **argv)
{
    if (argc != 5) {
        return usage(argv[0]);
    }

    const char *mode = argv[1];
    const char *ip = argv[2];
    int port = atoi(argv[3]);
    const char *file = argv[4];

    if (strcmp(mode, "client") == 0) {
        return run_client(ip, port, file);
    } else if (strcmp(mode, "server") == 0) {
        return run_server(ip, port, file);
    } else {
        return usage(argv[0]);
    }
    return 0;
}
