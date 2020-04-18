/*
 Program uruchamiamy z dwoma parametrami: nazwa serwera i numer jego portu.
 Program spróbuje połączyć się z serwerem, po czym będzie od nas pobierał
 linie tekstu i wysyłał je do serwera.  Wpisanie BYE kończy pracę.
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "err.h"

#define BUFFER_SIZE 1<<20
#define TMP_SIZE 1024
char buf[BUFFER_SIZE];
char tmp[TMP_SIZE];
char line[TMP_SIZE];

char bye_string[] = "BYE";

void get_ip_port(char *ip_port, char **addr, char **port) {
    *addr = strtok(ip_port, ":");
    *port = strtok(NULL, ":");
}

int bytes_added(result_of_sprintf) {
    return (result_of_sprintf > 0) ? result_of_sprintf : 0;
}

ssize_t create_request_str(char *dest, char *uri, char *addr, char *port,
                           FILE *cookies_file) {
    size_t length = 0;
#define buf_append(format, args...) length += bytes_added(sprintf(dest + length, format, args))
    buf_append("GET %s HTTP/1.1\r\n", uri);
    buf_append("Host %s:%s\r\n", addr, port);
    buf_append("User-Agent: %s\r\n", "testhttp_raw/2.13.7");
    buf_append("Accept: %s\r\n", "*/*");
    buf_append("Connection: %s\r\n", "close");
    while (fgets(tmp, sizeof tmp, cookies_file)) {
        tmp[strlen(tmp) - 1] = '\0'; // Remove trailing newline from fgets.
        buf_append("Cookie: %s\r\n", tmp);
    }
    buf_append("\r\n", NULL); // End of request
    return length;
}

//char* cookies

int main(int argc, char *argv[]) {
    int rc;
    int sock;
    struct addrinfo addr_hints, *addr_result;

    /* Kontrola dokumentów ... */
    if (argc != 4) {
        fatal("%s <adres połączenia>:<port> <plik ciasteczek> <testowany adres http>",
              argv[0]);
    }
    char *addr, *port, *cookie_filename, *uri;
    get_ip_port(argv[1], &addr, &port);
    cookie_filename = argv[2];
    uri = argv[3];
    FILE* cookies = fopen(cookie_filename, "r");

    create_request_str(buf, uri, addr, port, cookies);
    fclose(cookies);
    puts(buf);
    return 0;

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        syserr("socket");
    }

    /* Trzeba się dowiedzieć o adres internetowy serwera. */
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

    do {
        printf("line:");
        fgets(line, sizeof line, stdin);
        if (write(sock, line, strlen(line)) < 0)
            syserr("writing on stream socket");
    } while (strncmp(line, bye_string, sizeof bye_string - 1));
    if (close(sock) < 0)
        syserr("closing stream socket");

    return 0;
}

