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
#define BUFFER_SIZE 256
#define TMP_SIZE 65536
#define CRLF "\r\n"
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

size_t
read_headers(int sock, char **status_line, bool *chunked, ssize_t *content_len);

ssize_t parse_header_line1(int sock, char **line_ret, size_t *retrieve);

ssize_t find_crlf(const char *str, size_t len);

int parse_header_line(char *line, size_t line_len, char **status_line,
                      bool *chunked, ssize_t *content_len);

void move_buffer_content(char *buf, size_t parsed, size_t read);

bool starts_with(const char *s, const char *with_str, size_t s_len);

HeaderField classify_header_field(const char *header_line, size_t line_len);

size_t get_header_field_value_len(const char *value_begin, size_t line_len);

void handle_cookie(char *value_begin, size_t line_len);

void get_ip_port(char *ip_port, char **addr, char **port) {
    *addr = strtok(ip_port, ":");
    *port = strtok(NULL, ":");
}

int bytes_added(int result_of_sprintf) {
    return (result_of_sprintf > 0) ? result_of_sprintf : 0;
}

ssize_t create_request_str(char *dest, char *uri, char *addr, char *port,
                           FILE *cookies_file) {
    // TODO: Refactor the function to write directly to socket! Remove
    // TODO: sprintf in printing cookies (possibly null byte there)!
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

void argparse(int argc, char *argv[], char **addr, char **port,
              char **cookie_filename, char **uri) {
    if (argc != 4) {
        fatal("%s <adres połączenia>:<port> <plik ciasteczek> <testowany adres http>",
              argv[0]);
    }
    get_ip_port(argv[1], addr, port);
    *cookie_filename = argv[2];
    *uri = argv[3];
}

void send_request(int sock, char *request_str, size_t request_len) {
    ssize_t write_size;
    size_t req_wrote = 0;
    // Make sure to send the whole request.
    while (req_wrote < request_len &&
           (write_size = write(sock, request_str + req_wrote,
                               request_len - req_wrote))
           > 0) {
        req_wrote += write_size;
    }
    if (write_size < 0)
        syserr("writing on stream socket");
}

void print_line(const char *line, const size_t len) {
    // TODO: error check
    fwrite(line, len, sizeof(char), stdout);
    putc('\n', stdout);
}


size_t delim_position(const char *str, const char delim) {
    size_t res = 0; // Assumption: such character or \r\n exists somewhere in header.
    while (str[res] != delim && !(str[res] == '\r' && str[res + 1] == '\n'))
        ++res;
    return res;
}

int main(int argc, char *argv[]) {
    char *addr, *port, *cookie_filename, *uri;
    argparse(argc, argv, &addr, &port, &cookie_filename, &uri);

    FILE *cookies = fopen(cookie_filename, "r");
    if (cookies == NULL)
        syserr("cannot open cookie file");
    ssize_t req_len = create_request_str(buf, uri, addr, port, cookies);
    fclose(cookies);

    int sock = create_socket(addr, port);
    send_request(sock, buf, req_len);

//    char *line;
//    size_t status_line_len = read_status_line(sock, &line);
//    if (status_line_len > 0) {
//        print_line(line, status_line_len);
//        return 0;
//    }

    bool chunked = false;
    ssize_t content_len = -1, content_read_in_buffer = 0;
    char *status_line = NULL;
    content_read_in_buffer = read_headers(sock, &status_line, &chunked,
                                          &content_len);
    if (status_line != NULL) {
        print_line(buf, content_read_in_buffer);
        return 0;
    }

    size_t read_content_len = read_content(sock, content_read_in_buffer,
                                           chunked);
////    assert(chunked || read_content_len == content_len);
//
////    content_len = chunked ? read_content_len : content_len;
////    assert(total_read >= content_len);
    printf("Dlugosc zasobu: %zu\n", read_content_len);

    if (close(sock) < 0)
        syserr("closing stream socket");
    return 0;
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

#define CRLF_LEN 2
#define CHUNKED_LEN 7
#define STATUS_LEN 9
#define SET_COOKIE_LEN 12
#define CONTENT_LENGTH_LEN 16
#define TRANSFER_ENC_LEN 19

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
    size_t chars_read = 0, chars_parsed = 0, received = 0;
    ssize_t current_line_len = -1; // TODO: maybe leave \r\n instead of chunksize first
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
//        assert(current_line_len != -1);
        if (current_line_len == 0 || chars_read == BUFFER_SIZE) {
//            if(chars_parsed == 0)
//                syserr("buffer overflow");
            move_buffer_content(buf, chars_parsed, chars_read);
            chars_read -= chars_parsed;
            // TODO: fix \r\n splitted in the middle!
            chars_parsed = 0;
        }
    }
    assert(chars_read >= chars_parsed);
    return chars_read;
}

void move_buffer_content(char *buffer, size_t parsed, size_t read) {
    memmove(buffer, buf + parsed, read - parsed);
}

int parse_header_line(char *line, size_t line_len, char **status_line,
                      bool *chunked, ssize_t *content_len) {
    static const char *_CHUNKED = "chunked";
    static const char *_STATUS_200 = "200";
//    fwrite(line, line_len, 1, stderr);
//    putc('\n', stderr);
    HeaderField hf = classify_header_field(line, line_len);
    switch (hf) {
        case STATUS:
            if (strncasecmp(line + STATUS_LEN, _STATUS_200, 3) != 0) {
                *status_line = line;
                return 1;
            }
            break;
        case SET_COOKIE:
            handle_cookie(line + SET_COOKIE_LEN, line_len - SET_COOKIE_LEN);
            break;
        case CONTENT_LENGTH:
            // TODO: better
            *content_len = strtoul(line + CONTENT_LENGTH_LEN, NULL, 10);
            break;
        case TRANSFER_ENCODING:
            *chunked = starts_with(line + TRANSFER_ENC_LEN, _CHUNKED,
                                   min(line_len - TRANSFER_ENC_LEN,
                                       (CHUNKED_LEN)));
            break;
        default:
            break;
    }
    return 0;
}

void handle_cookie(char *value_begin, size_t line_len) {
    size_t true_len = get_header_field_value_len(value_begin, line_len);
    print_line(value_begin, true_len);
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

/**
 *
 * @param sock
 * @param line_ret
 * @param retrieve
 * @return
 */
ssize_t parse_header_line1(int sock, char **line_ret, size_t *retrieve) {
    static size_t offset = 0;
    static size_t read_till = 0;
    if (retrieve != NULL) {
        *retrieve = read_till;
        return offset;
    }

    static size_t _no_reads = 0;

    char *crlf_position = NULL;
    size_t line_len;
    assert(buf[read_till] == '\0');
//    fprintf(stderr, "Read till: %zu\n", read_till);

    while (offset == read_till ||
           !(crlf_position = strstr(buf + offset, CRLF))) {
        if (read_till == BUFFER_SIZE - 1) {
            if (read_till == offset)
                syserr("buffer overflow");
            read_till -= offset;
            memmove(buf, buf + offset, read_till);
            offset = 0;
        } else {
            offset = read_till; // TODO: fragment?
//            offset = read_till - (buf[read_till - 1] == '\r');
        }
        assert(read_till < BUFFER_SIZE - 1); // We don't want to read 0 bytes.

        ssize_t resp_len;
        while ((resp_len = read(
                sock, buf + read_till, BUFFER_SIZE - read_till - 1)) > 0) {
//            fprintf(stderr, "Reads so far: %zu\n", ++_no_reads);
            assert(offset + resp_len < BUFFER_SIZE);
            read_till += resp_len;
            assert(offset < read_till);
        }
        if (resp_len < 0)
            syserr("response read error");
        buf[read_till] = '\0';
//        if (read_till == BUFFER_SIZE - 1) {
//            if ((crlf_position = strstr(buf + offset, CRLF)))
//                break;
//            else if (offset > 0) {
//                read_till -= offset;
//                memmove(buf, buf + offset, read_till);
//                offset = 0;
//            } else {
//                return -1; // Buffer overflow.
//            }
//        }
        assert(offset < read_till);
    }

    *line_ret = buf + offset;
    line_len = (crlf_position - *line_ret);
    // Found CRLF!!!
    assert(offset + line_len < BUFFER_SIZE && buf[offset + line_len] == '\r'
           && buf[offset + line_len + 1] == '\n');
    buf[offset + line_len] = '\0';
    offset += line_len + 2;
    assert(line_len == 0 || offset < read_till);
    return line_len;
}

size_t get_header_field_value_len(const char *value_begin, size_t line_len) {
    static const char DELIM = ';';
    char *delim_pos = memchr(value_begin, DELIM, line_len);
    return (delim_pos == NULL) ? line_len : delim_pos - value_begin;
}
