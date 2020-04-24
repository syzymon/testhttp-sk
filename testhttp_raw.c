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

#define BUFFER_SIZE 8388608
#define TMP_SIZE 65536
#define CRLF "\r\n"
#define CRLF_LEN 2
#define CHUNKED_LEN 7
#define STATUS_LEN 9
#define SET_COOKIE_LEN 12
#define CONTENT_LENGTH_LEN 16
#define TRANSFER_ENC_LEN 19
#define min(a, b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b;       \
})

char buf[BUFFER_SIZE];
char tmp[TMP_SIZE];

typedef enum HeaderField {
    STATUS = 0,
    SET_COOKIE = 1,
    CONTENT_LENGTH = 2,
    TRANSFER_ENCODING = 3,
    OTHER = 4
} HeaderField;

size_t receive_response(int sock, char *buffer, size_t max_to_read);

size_t
read_headers(int sock, char **status_line, bool *chunked, ssize_t *content_len);

ssize_t find_crlf(const char *str, size_t len);

int parse_header_line(char *line, size_t line_len, char **status_line,
                      bool *chunked, ssize_t *content_len);

void move_buffer_content(char *buf, size_t parsed, size_t read);

bool starts_with(const char *s, const char *with_str, size_t s_len);

HeaderField classify_header_field(const char *header_line, size_t line_len);

size_t get_header_field_value_len(const char *value_begin, size_t line_len);

void handle_cookie(char *value_begin, size_t line_len);

void parse_addr_port(char *ip_port, char **addr, char **port);

size_t send_bytes(int sock, char *bytes, size_t n_bytes);

int bytes_added(int result_of_sprintf) {
    return (result_of_sprintf > 0) ? result_of_sprintf : 0;
}

void send_request(int sock, char *uri, char *addr, char *port,
                  FILE *cookies_file);

size_t read_content(int sock, size_t resp_read, bool chunked);

int create_socket(const char *addr, const char *port);

void argparse(int argc, char *argv[], char **addr, char **port,
              char **cookie_filename, char **uri);

void print_line(const char *line, const size_t len) {
    fwrite(line, len, sizeof(char), stdout);
    fputc('\n', stdout);
}

int main(int argc, char *argv[]) {
    char *addr, *port, *cookie_filename, *uri;
    argparse(argc, argv, &addr, &port, &cookie_filename, &uri);

    int sock = create_socket(addr, port);

    FILE *cookies = fopen(cookie_filename, "r");
    if (cookies == NULL) {
        syserr("cannot open cookie file");
    }
    send_request(sock, uri, addr, port, cookies);
    fclose(cookies);

    bool chunked = false;
    ssize_t content_len = -1, content_read_in_buffer;
    char *status_line = NULL;
    content_read_in_buffer = read_headers(sock, &status_line, &chunked,
                                          &content_len);
    if (status_line != NULL) {
        print_line(buf, content_read_in_buffer);
        return 0;
    }

    size_t read_content_len = read_content(sock, content_read_in_buffer,
                                           chunked);

    printf("Dlugosc zasobu: %zu\n", read_content_len);

    if (close(sock) < 0)
        syserr("closing stream socket");
    return 0;
}


void argparse(int argc, char **argv, char **addr, char **port,
              char **cookie_filename, char **uri) {
    if (argc != 4) {
        fatal("%s <adres połączenia>:<port> <plik ciasteczek> <testowany adres http>",
              argv[0]);
    }
    parse_addr_port(argv[1], addr, port);
    if (*port == NULL || *addr == NULL)
        fatal("brak adresu lub numeru portu");
    *cookie_filename = argv[2];
    *uri = argv[3];
}

void parse_addr_port(char *ip_port, char **addr, char **port) {
    *addr = strtok(ip_port, ":");
    *port = strtok(NULL, ":");
}

int create_socket(const char *addr, const char *port) {
    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        syserr("socket");
    }

    struct addrinfo addr_hints, *addr_result;
    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_flags = 0;
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;

    int rc = getaddrinfo(addr, port, &addr_hints, &addr_result);
    if (rc != 0) {
        fprintf(stderr, "rc=%d\n", rc);
        syserr("getaddrinfo: %s", gai_strerror(rc));
    }

    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) != 0) {
        syserr("connect");
    }
    freeaddrinfo(addr_result);
    return sock;
}

size_t send_bytes(int sock, char *bytes, size_t n_bytes) {
    ssize_t write_size;
    size_t req_wrote = 0;
    while (req_wrote < n_bytes &&
           (write_size = write(sock, bytes + req_wrote,
                               n_bytes - req_wrote))
           > 0) {
        req_wrote += write_size;
    }
    if (write_size < 0)
        syserr("writing on stream socket");
    return req_wrote;
}


/**
 * Read maximum of `max_to_read` bytes from `sock` into `buffer`.
 * @param sock - Socket fd to read from.
 * @param buffer - pointer to the buffer where received data will be saved.
 * @param max_to_read - maximum number of bytes to read.
 * @return number of bytes successfully read.
 */
size_t receive_response(int sock, char *buffer, size_t max_to_read) {
    size_t total_received_len = 0;
    ssize_t read_res;
    while ((read_res = read(
            sock, buffer + total_received_len,
            max_to_read - total_received_len)) > 0) {
        total_received_len += read_res;
    }
    if (read_res < 0)
        syserr("response read error");
    return total_received_len;
}

void
send_request(int sock, char *uri, char *addr, char *port, FILE *cookies_file) {
    size_t length = 0;
#define buf_append(format, args...) \
    length += bytes_added(sprintf(buf + length, format, args))
    buf_append("GET %s HTTP/1.1\r\n", uri);
    buf_append("Host: %s:%s\r\n", addr, port);
    buf_append("User-Agent: %s\r\n", "testhttp_raw/2.13.7");
    buf_append("Accept: %s\r\n", "*/*");
    buf_append("Connection: %s\r\n", "close");
    size_t sent = send_bytes(sock, buf, length);

    assert(sent == length);

    while (fgets(tmp, sizeof tmp, cookies_file)) {
        size_t cookie_line_len = strlen(tmp);
        if (cookie_line_len >= 2 && tmp[cookie_line_len - 2] == '\r')
            tmp[cookie_line_len - 2] = '\0';
        else
            tmp[cookie_line_len - 1] = '\0';
        sprintf(buf, "Cookie: %s\r\n", tmp);
        sent = send_bytes(sock, buf, strlen(buf));
        assert(sent == strlen(buf));
    }
    sent = send_bytes(sock, CRLF, CRLF_LEN);
    assert(sent == CRLF_LEN);
}

/**
 * Reads headers from given socket to the buffer, parsing parameters that we
 * look for line by line (chunked, content length, cookies) and outputs cookies
 * to stdout. After header finishes (double \r\n encountered) it moves the
 * rest of bytes read from the socket so that the first unparsed byte is the
 * first character in the buffer, and returns number of read but unparsed bytes.
 * @param sock - File descriptor of socket that will be read from.
 * @param status_line - (return value) Status line of the response.
 * @param chunked - (return value) True if Transfer-Encoding: chunked header
 * encountered.
 * @param content_len - (return value) Value of Content-Length header if
 * encountered, -1 otherwise.
 * @return number of not parsed content bytes in the buffer (after header ended)
 * already read from socket
 */
size_t read_headers(int sock, char **status_line, bool *chunked,
                    ssize_t *content_len) {
    assert(*status_line == NULL);
    size_t chars_read = 0, chars_parsed = 0, received;
    ssize_t current_line_len = -1;
    while (current_line_len != 0 &&
           (received = receive_response(sock, buf + chars_read,
                                        BUFFER_SIZE - chars_read)) > 0) {
        chars_read += received;
        assert(chars_read <= BUFFER_SIZE);
        while (chars_parsed < chars_read && (current_line_len = find_crlf(
                buf + chars_parsed, chars_read - chars_parsed)) >= 0) {
            int status = parse_header_line(
                    buf + chars_parsed, current_line_len, status_line,
                    chunked, content_len
            );
            if (status != 0) {
                return current_line_len;
            }
            chars_parsed += current_line_len + CRLF_LEN;
            if (current_line_len == 0)
                break;
            assert(chars_parsed <= chars_read);
        }

        if (current_line_len == 0 || chars_read == BUFFER_SIZE) {

            move_buffer_content(buf, chars_parsed, chars_read);
            chars_read -= chars_parsed;
            chars_parsed = 0;
        }
    }
    assert(chars_read >= chars_parsed);
    return chars_read;
}


int parse_header_line(char *line, size_t line_len, char **status_line,
                      bool *chunked, ssize_t *content_len) {
    static const char *CHUNKED = "chunked";
    static const char *STATUS_200 = "200";

    HeaderField hf = classify_header_field(line, line_len);
    switch (hf) {
        case STATUS:
            if (strncasecmp(line + STATUS_LEN, STATUS_200, 3) != 0) {
                *status_line = line;
                return 1;
            }
            break;
        case SET_COOKIE:
            handle_cookie(line + SET_COOKIE_LEN, line_len - SET_COOKIE_LEN);
            break;
        case CONTENT_LENGTH:
            *content_len = strtoul(line + CONTENT_LENGTH_LEN, NULL, 10);
            break;
        case TRANSFER_ENCODING:
            *chunked = (line_len - TRANSFER_ENC_LEN >= CHUNKED_LEN) &&
                       starts_with(line + TRANSFER_ENC_LEN, CHUNKED,
                                   CHUNKED_LEN);
            break;
        default:
            break;
    }
    return 0;
}

HeaderField classify_header_field(const char *header_line, size_t line_len) {
    static const char *SET_COOKIE_ = "Set-Cookie: ";
    static const char *STATUS_ = "HTTP/1.1 ";
    static const char *TRANSFER_ENCODING_ = "Transfer-Encoding: ";
    static const char *CONTENT_LEN_ = "Content-Length: ";
    if (line_len >= SET_COOKIE_LEN &&
        starts_with(header_line, SET_COOKIE_, SET_COOKIE_LEN))
        return SET_COOKIE;
    else if (line_len >= STATUS_LEN &&
             starts_with(header_line, STATUS_, STATUS_LEN))
        return STATUS;
    else if (line_len >= TRANSFER_ENC_LEN &&
             starts_with(header_line, TRANSFER_ENCODING_,
                         min(line_len, TRANSFER_ENC_LEN)))
        return TRANSFER_ENCODING;
    else if (line_len >= CONTENT_LENGTH_LEN &&
             starts_with(header_line, CONTENT_LEN_,
                         min(line_len, CONTENT_LENGTH_LEN)))
        return CONTENT_LENGTH;
    else
        return OTHER;
}

void handle_cookie(char *value_begin, size_t line_len) {
    size_t true_len = get_header_field_value_len(value_begin, line_len);
    print_line(value_begin, true_len);
}

size_t get_header_field_value_len(const char *value_begin, size_t line_len) {
    static const char DELIM = ';';
    char *delim_pos = memchr(value_begin, DELIM, line_len);
    return (delim_pos == NULL) ? line_len : delim_pos - value_begin;
}

/**
 * Checks if char sequence `s` contains `with_str` as a prefix, where `with_str`
 * is a null-terminated string.
 * @param s - A sequence of characters, not necessarily null-terminated.
 * @param with_str - Desired prefix, a null-terminated string.
 * @param s_len - Length of `s`.
 * @return true if `s` contains `with_str` as a prefix.
 */
bool starts_with(const char *s, const char *with_str, size_t len) {
    return strncasecmp(s, with_str, len) == 0;
}

/**
 * Returns position of the first occurrence of \r\n from the beginning of the
 * given `str` sequence of characters (null bytes allowed in the middle).
 * @param str - String where search will be performed.
 * @param len - Given string length (zero characters allowed in the middle).
 * @return position of the first CRLF occurrence or -1 if no CRLF found.
 */
ssize_t find_crlf(const char *str, size_t len) {
    ssize_t res = 0;
    while (res + 1 < len && (str[res] != '\r' || str[res + 1] != '\n')) ++res;
    return (res + 1 == len) ? -1 : res;
}

size_t read_content(int sock, size_t resp_read, bool chunked) {
    size_t content_len = 0;
    size_t chunk_size_pos = 0;
    size_t chunk_size_fragmented = 0;

    size_t _total_read = 0;
    size_t _no_chunks = 0;
    size_t _chunksize_lens = 0;

    size_t read_len = 0;
    while (resp_read > 0 ||
           (read_len = receive_response(sock, buf + resp_read,
                                        BUFFER_SIZE - resp_read)) > 0) {
        resp_read += read_len;
        _total_read += resp_read;

        if (chunked) {
            while (chunk_size_pos < resp_read) {
                assert((chunk_size_fragmented > 0 &&
                        (buf[chunk_size_pos] == '\r' ||
                         buf[chunk_size_pos] == '\n')) ||
                       isxdigit(*(buf + chunk_size_pos)));

                char *cr_pos = memchr(buf + chunk_size_pos, '\r',
                                      resp_read - chunk_size_pos);
                size_t chunk_size_len = (cr_pos == NULL) ? (resp_read -
                                                            chunk_size_pos) :
                                        (cr_pos - (buf + chunk_size_pos));

                memcpy(tmp + chunk_size_fragmented, buf + chunk_size_pos,
                       chunk_size_len);
                assert(chunk_size_pos + chunk_size_len <=
                       resp_read);

                if (chunk_size_pos + chunk_size_len == resp_read) {
                    chunk_size_fragmented = chunk_size_len;
                    chunk_size_pos += chunk_size_len;
                } else {
                    assert(*(buf + chunk_size_pos +
                             chunk_size_len) == '\r');
                    ++_no_chunks;
                    _chunksize_lens += chunk_size_len + chunk_size_fragmented;
                    tmp[chunk_size_fragmented + chunk_size_len] = '\0';
                    size_t chunk_size = strtoul(tmp, NULL, 16);
                    // The end of chunked message is determined by a zero-chunk
                    if (chunk_size == 0) // so we know the correct length now.
                        return content_len;
                    content_len += chunk_size;
                    chunk_size_pos += (chunk_size + chunk_size_len +
                                       2 * CRLF_LEN);
                    chunk_size_fragmented = 0;
                }
            }
            chunk_size_pos -= resp_read;
        } else {
            content_len += resp_read;
        }
        resp_read = 0;
    }
    assert(!chunked ||
           (_total_read ==
            content_len + _no_chunks * CRLF_LEN * 2 + _chunksize_lens
            && chunk_size_pos == 0));
    return content_len;
}

void move_buffer_content(char *buffer, size_t parsed, size_t read) {
    memmove(buffer, buf + parsed, read - parsed);
}
