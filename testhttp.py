#!/usr/bin/python3
import os
import socket
import subprocess
import argparse
from urllib.parse import urlparse

SERVICE_IP = "127.0.0.1"
PID_FILE = "/tmp/stunnel.pid"

service_config_template = \
    """pid = {}
[service]
client = yes
accept = {}
connect = {}"""


def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port


def create_config_str(service_netloc, connect_netloc):
    return service_config_template.format(PID_FILE, service_netloc,
                                          connect_netloc)


def run_testhttp(server_netloc, cookies, uri):
    subprocess.run(["./testhttp_raw", server_netloc, cookies, uri])


def run_testhttps(server_netloc, cookies, uri):
    free_port = get_free_tcp_port()
    service_netloc = "{}:{}".format(SERVICE_IP, free_port)
    config_input = create_config_str(service_netloc, server_netloc)
    subprocess.run(["stunnel", "-fd", "0"], universal_newlines=True,
                   input=config_input)

    run_testhttp(service_netloc, cookies, uri)

    with open(PID_FILE) as pid_file:
        pid = int(pid_file.readline())
        os.kill(pid, 9)
    os.remove(PID_FILE)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cookies", help="Path to file with cookies")
    parser.add_argument("url",
                        help="http or https address, optionally with port")
    args = parser.parse_args()

    parsed_url = urlparse(args.url)
    netloc = parsed_url.netloc
    if not parsed_url.port:
        netloc += (":443" if parsed_url.scheme == "https" else ":80")

    if parsed_url.scheme == "http":
        run_testhttp(netloc, args.cookies, args.url)
    else:
        run_testhttps(netloc, args.cookies, args.url)
