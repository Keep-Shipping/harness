#!/usr/bin/env python3
"""example-api: the smallest thing that answers a request.

Standard library only, so `docker build` needs nothing but the base image.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", "8080"))
VERSION = os.environ.get("VERSION", "dev")


class Handler(BaseHTTPRequestHandler):
    """One route: `GET /` says what is running and answers."""

    def do_GET(self):  # noqa: N802 - the name BaseHTTPRequestHandler requires
        if self.path != "/":
            self.send_error(404, "not found")
            return
        body = json.dumps({"service": "example-api", "version": VERSION}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    print(f"example-api {VERSION} listening on :{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()