import os
import json
import requests
import secrets
import ssl
import sys
import time
import webbrowser

from argparse import ArgumentParser
from ctypes import c_bool
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer
from multiprocessing import Value, process
from multiprocessing.dummy import Process, Queue
from pathlib import Path
from string import ascii_lowercase
from typing import Any, Optional
from urllib.parse import parse_qs

LOGGING_ENABLED = False
RESPONSE_TYPE = "id_token"
RESPONSE_MODE = "form_post"


def log(message: Any):
    if LOGGING_ENABLED:
        print(message)


def safe_remove(path: Any):
    if path is not None:
        try:
            os.remove(path)
        except OSError:
            pass


class ExtractTokenRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, endpoint: str, token_queue: Queue, *args, **kwargs):
        self.endpoint = endpoint
        self.token_queue = token_queue
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        self.send_response_only(404)
        self.send_header("Content-Length", 0)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_POST(self) -> None:
        if self.path == f"/{self.endpoint}":
            content_len = int(self.headers.get("Content-Length"))
            params = parse_qs(self.rfile.read(content_len))

            if "error" in params:
                log(params)
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()

                message = json.dumps(params)
                self.wfile.write(bytes(message, "utf8"))
                return

            id_token = params.get(b'id_token')[0].decode("utf-8")

            self.send_response_only(code=200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            message = "Success"
            self.wfile.write(bytes(message, "utf8"))
            self.end_headers()

            # Drop the shutdown marker so the main thread can exit
            self.token_queue.put(id_token)
        else:
            self.send_response_only(404)
            self.send_header("Content-Length", 0)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Connection", "close")
            self.end_headers()


if __name__ == "__main__":
    parser = ArgumentParser(description="""OAuth 2.0 authentication client.
                                            Executes the implicit grant authentication flow, obtaining an ID token with the openid scope.

                                            For example:
                                                generate_id_token.py https://accounts.google.com xxx-client-id

                                            Additional scopes may be requested using the --scopes argument:
                                                generate_id_token.py https://accounts.google.com xxx-client-id --scopes profile email ocient:battleship:analyst

                                            Use --help for info on additional arguments
                                         """)

    parser.add_argument("-p", "--port", type=int, default="4553",
                        help="The port used to receive the ID Token redirect response")
    parser.add_argument("-e", "--endpoint", type=str, default="callback",
                        help="The endpoint used to receive the ID Token redirect response")
    parser.add_argument("-k", "--key", type=str, default=None,
                        help="The private SSL key for the script's local server")
    parser.add_argument("-v", "--verbose", default=False,
                        help="Enable debug logging", action="store_true")
    parser.add_argument('-o', '--outfile', type=str,
                        default=None, help="Output file for ID token")
    parser.add_argument("--poll_interval", type=int, default="1",
                        help="The server's polling interval in seconds")
    parser.add_argument('-s', '--scopes', nargs='+',
                        default=[], help="Additional scopes to request")
    parser.add_argument("issuer", type=str, help="The OpenID Connect issuer")
    parser.add_argument("client_id", type=str,
                        help="The OpenID Connect client_id of the Relying Party")

    # Parse CLI args
    args = parser.parse_args(sys.argv[1:])
    if not args.key:
        args.key = f"{os.getcwd()}/cert/server.pem"

    LOGGING_ENABLED = args.verbose

    scopes = ["openid"]
    scopes.extend(args.scopes)

    # Step 1) Retrieve the authorization URL from the OpenID provider's discovery document
    discovery_document_rsp = requests.get(
        f"{args.issuer}/.well-known/openid-configuration")
    discovery_document_rsp.raise_for_status()
    discovery_document = discovery_document_rsp.json()
    authorization_url = discovery_document["authorization_endpoint"]
    log(discovery_document)

    # Step 2) Prepare, but don't fire authorization request to the OpenID provider
    redirect_uri = f"https://localhost:{args.port}/{args.endpoint}"
    nonce = secrets.token_urlsafe(32)
    params = dict(
        response_type=RESPONSE_TYPE,
        client_id=args.client_id,
        scope=" ".join(scopes),
        redirect_uri=redirect_uri,
        response_mode=RESPONSE_MODE,
        nonce=nonce,
        state="12345"
    )
    req = requests.Request("GET", authorization_url, params=params).prepare()

    # Step 3) Fire auth request from the user's default user agent
    log(f"Opening {req.url}")
    webbrowser.open(req.url, new=0)

    token_queue = Queue()

    # Step 4) Start the server which will listen for the redirect response from the idP containing the id token
    log("Starting server to handle authorization redirect")

    log(f"CWD: {os.getcwd()}")
    log(f"Server key: {args.key}")

    server = HTTPServer(server_address=("localhost", args.port), RequestHandlerClass=partial(
        ExtractTokenRequestHandler, args.endpoint, token_queue))
    server.socket = ssl.wrap_socket(
        server.socket, certfile=args.key, server_side=True)
    server_thread = Process(target=server.serve_forever, kwargs={
                            "poll_interval": args.poll_interval})
    server_thread.start()

    # Step 5) Wait for end user to complete authentication
    id_token = token_queue.get(block=True)

    time.sleep(3)

    if args.outfile is not None:
        with open(args.outfile, "w") as f:
            print(id_token, file=f)
    else:
        print(id_token)

    log("Shutting down server")
    server.shutdown()

    log("Joining server thread")
    server_thread.join()
