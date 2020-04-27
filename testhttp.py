#!/usr/bin/python3
import os
import socket
import subprocess
import argparse
from urllib.parse import urlparse
from pathlib import Path

SERVICE_IP = "127.0.0.1"
PID_PATH = Path("/tmp/stunnel.pid")

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
    return service_config_template.format(str(PID_PATH), service_netloc,
                                          connect_netloc)


def run_testhttp(server_netloc, cookies, uri):
    raw_path = Path(__file__).parent.resolve() / 'testhttp_raw'
    subprocess.run([raw_path, server_netloc, cookies, uri])


def run_testhttps(server_netloc, cookies, uri):
    try:
        free_port = get_free_tcp_port()
        service_netloc = "{}:{}".format(SERVICE_IP, free_port)
        config_input = create_config_str(service_netloc, server_netloc)
        subprocess.run(["stunnel", "-fd", "0"], universal_newlines=True,
                       input=config_input)

        run_testhttp(service_netloc, cookies, uri)
    finally:
        if PID_PATH.exists():
            pid = int(PID_PATH.read_text())
            os.kill(pid, 9)
            PID_PATH.unlink()


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
