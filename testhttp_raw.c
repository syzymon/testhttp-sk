#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <ctype.h>
#include "err.h"

// TODO: production TMP and buffer size
#define BUFFER_SIZE 65536
#define TMP_SIZE 65536
#define CRLF "\r\n"
char buf[BUFFER_SIZE];
char tmp[TMP_SIZE];

void get_ip_port(char *ip_port, char **addr, char **port) {
    *addr = strtok(ip_port, ":");
    *port = strtok(NULL, ":");
}

int bytes_added(int result_of_sprintf) {
    return (result_of_sprintf > 0) ? result_of_sprintf : 0;
}

ssize_t create_request_str(char *dest, char *uri, char *addr, char *port,
                           FILE *cookies_file) {
    size_t length = 0;
#define buf_append(format, args...) \
    length += bytes_added(sprintf(dest + length, format, args))
    buf_append("GET %s HTTP/1.1\r\n", uri);
    buf_append("Host: %s:%s\r\n", addr, port);
    buf_append("User-Agent: %s\r\n", "testhttp_raw/2.13.7");
    buf_append("Accept: %s\r\n", "*/*");
    buf_append("Connection: %s\r\n", "close");
    while (fgets(tmp, sizeof tmp, cookies_file)) {
        tmp[strlen(tmp) - 1] = '\0'; // Remove trailing newline from fgets.
        buf_append("Cookie: %s\r\n", tmp);
    }
    length += bytes_added(sprintf(dest + length, CRLF)); // End of request
    return length;
}

ssize_t get_line_from_sock(int sock, char **line_ret) {
    static size_t offset = 0;
    static size_t read_till = 0;

    static size_t no_reads = 0;

    char *crlf_position = NULL;
    size_t line_len;
    assert(buf[read_till] == '\0');
//    fprintf(stderr, "Read till: %zu\n", read_till);

    while (!(crlf_position = strstr(buf + offset, CRLF))) {
        if (offset < read_till && read_till == BUFFER_SIZE - 1) {
            read_till -= offset;
            memmove(buf, buf + offset, read_till);
            offset = 0;
        } else {
            offset = read_till;
        }
        assert(read_till < BUFFER_SIZE - 1); // We don't want to read 0 bytes.

        ssize_t resp_len = read(
                sock, buf + read_till, BUFFER_SIZE - read_till - 1);
        if (resp_len < 0)
            syserr("response read error");

        fprintf(stderr, "Reads so far: %zu\n", ++no_reads);

        assert(offset + resp_len < BUFFER_SIZE);
        read_till += resp_len;
        assert(offset < read_till);

        buf[read_till] = '\0';
        if (read_till == BUFFER_SIZE - 1) {
            if ((crlf_position = strstr(buf + offset, CRLF)))
                break;
            else if (offset > 0) {
                read_till -= offset;
                memmove(buf, buf + offset, read_till);
                offset = 0;
            } else {
                return -1; // Buffer overflow.
            }
        }
        assert(offset < read_till);
    }

    *line_ret = buf + offset;
    line_len = (crlf_position - *line_ret);
    assert(offset + line_len < BUFFER_SIZE && buf[offset + line_len] == '\r'
           && buf[offset + line_len + 1] == '\n');
    buf[offset + line_len] = '\0';
    offset = offset + line_len + 2;
    assert(offset < read_till);
    return line_len;
}

size_t read_content(int sock, size_t resp_read, bool chunked) {
    size_t content_len = 0;
    size_t chunk_size_pos = 0;
    size_t chunk_size_fragmented = 0;

    size_t _total_read = 0;
    size_t _no_chunks = 0;
    size_t _chunksize_lens = 0;

    tmp[0] = '\0'; // TODO: necessary?

    do {
        if (resp_read == BUFFER_SIZE - 1)
            resp_read = 0;

        ssize_t read_len;
        while (resp_read < BUFFER_SIZE - 1 && (read_len = read(
                sock, buf + resp_read, BUFFER_SIZE - resp_read - 1
        )) > 0) {
            resp_read += read_len;
        }
        if (read_len == -1)
            syserr("response read error");

        _total_read += resp_read;

        buf[resp_read] = '\0';
        if (chunked) {
            // TODO: corner case - chunk size on the limit of buffer!
            while (chunk_size_pos < resp_read) {
                // TODO: falsy assert - isdigit + hex
//                assert(isdigit(*(buf + chunk_size_pos)));
                if (resp_read)
                    sscanf(buf + chunk_size_pos, "%[^\r\n]s",
                           tmp + chunk_size_fragmented);
                assert(chunk_size_pos + strlen(tmp + chunk_size_fragmented) <=
                       resp_read);
//                fprintf(stderr, "%s\n", tmp);

                if (chunk_size_pos + strlen(tmp) == resp_read) { // TODO: 2 o
                    chunk_size_fragmented = strlen(tmp);
                    chunk_size_pos += strlen(tmp);
                } else {
                    assert(*(buf + chunk_size_pos +
                             strlen(tmp + chunk_size_fragmented)) == '\r');
                    ++_no_chunks;
                    _chunksize_lens += strlen(tmp);

                    size_t chunk_size = strtoul(tmp, NULL, 16);
                    content_len += chunk_size;
                    chunk_size_pos += (chunk_size +
                                       strlen(tmp + chunk_size_fragmented) +
                                       4); // TODO: why?
                    chunk_size_fragmented = 0;
                }
            }
            chunk_size_pos -= resp_read;
        } else {
            content_len += resp_read;
        }
    } while (resp_read == BUFFER_SIZE - 1);
    assert(!chunked ||
           (_total_read == content_len + _no_chunks * 4 + _chunksize_lens
            && chunk_size_pos == 0));
    return content_len;
}

int main(int argc, char *argv[]) {
    int rc;
    int sock;
    struct addrinfo addr_hints, *addr_result;

    if (argc != 4) {
        fatal("%s <adres połączenia>:<port> <plik ciasteczek> <testowany adres http>",
              argv[0]);
    }
    char *addr, *port, *cookie_filename, *uri;
    get_ip_port(argv[1], &addr, &port);
    cookie_filename = argv[2];
    uri = argv[3];

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        syserr("socket");
    }

    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_flags = 0;
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;

    rc = getaddrinfo(addr, port, &addr_hints, &addr_result);
    if (rc != 0) {
        fprintf(stderr, "rc=%d\n", rc);
        syserr("getaddrinfo: %s", gai_strerror(rc));
    }

    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) != 0) {
        syserr("connect");
    }
    freeaddrinfo(addr_result);

    FILE *cookies = fopen(cookie_filename, "r");
    ssize_t req_len = create_request_str(buf, uri, addr, port, cookies);
    fclose(cookies);
//    char msg[] = "GET / HTTP/1.1\r\nHost: www.mimuw.edu.pl:80\r\n\r\n";
//    puts(msg);
//    fprintf(stderr, "%s", buf);
    ssize_t line_len;
    size_t req_wrote = 0;

    // Make sure to send the whole request.
    while (req_wrote < req_len &&
           (line_len = write(sock, buf + req_wrote, req_len - req_wrote))
           > 0) {
        req_wrote += line_len;
    }
    if (line_len < 0)
        syserr("writing on stream socket");

    char *line;
    buf[0] = '\0';
    if (get_line_from_sock(sock, &line) <= 0)
        syserr("bad HTTP response format");

    if (sscanf(line, "%*s %s", tmp) != 1)
        syserr("no response code detected");
    if (strcmp(tmp, "200") != 0) { // Response code different than 200 OK
        printf("%s\n", line);
        return 0;
    }

    bool chunked = false;
    ssize_t content_len = 0;
    while ((line_len = get_line_from_sock(sock, &line)) > 0) {
        int sscanf_read;
        if (sscanf(line, "%s%n", tmp, &sscanf_read) != 1)
            syserr("bad format");
        line += sscanf_read + 1; // Header name + whitespace
        // TODO: strcasecmp
        if (!strcasecmp(tmp, "Set-Cookie:")) {
            sscanf(line, "%[^;]s", tmp);
            printf("%s\n", tmp);
        } else if (!strcasecmp(tmp, "Transfer-Encoding:")) {
            sscanf(line, "%s", tmp);
            if (!strcasecmp(tmp, "chunked"))
                chunked = true;
        } else if (!strcasecmp(tmp, "Content-Length:")) {
            sscanf(line, "%zu", &content_len);
        }
    }
    if (line_len == -1)
        syserr("buffer overflow");
    assert(line_len == 0 && line[0] == '\0' && line[1] == '\n');
    // Copy the rest of read response
    line += 2;
    size_t resp_read = strlen(line);
    assert(resp_read < BUFFER_SIZE - 1);
    memmove(buf, line, resp_read);

    if (chunked) {
        fputs("CHUNKED\n", stderr);
    }
    size_t read_content_len = read_content(sock, resp_read, chunked);
    assert(chunked || read_content_len == content_len);

    content_len = chunked ? read_content_len : content_len;
//    assert(total_read >= content_len);
    printf("Dlugosc zasobu: %zu\n", content_len);

    if (close(sock) < 0)
        syserr("closing stream socket");
    return 0;
}

