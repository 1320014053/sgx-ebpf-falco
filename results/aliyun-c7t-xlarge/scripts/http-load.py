"""Two persistent HTTP/1.1 clients, each receiving a 1 KiB loopback response."""
import argparse
from collections import Counter
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from pathlib import Path
import sys
import threading
import time

BODY = bytes(1024)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


def measure(args):
    histograms = [Counter(), Counter()]
    completions = [Counter(), Counter()]
    errors = []
    start = end = 0

    def release():
        nonlocal start, end
        if args.gate:
            print("ready", flush=True)
            if not sys.stdin.buffer.read(1):
                raise RuntimeError("workload gate closed")
        start = time.monotonic_ns()
        end = start + int(args.seconds * 1e9)

    gate = threading.Barrier(2, action=release)
    period = int(1e9 / args.rate) if args.rate else 0

    def client(hist, counts):
        conn = HTTPConnection("127.0.0.1", args.port, timeout=5)
        try:
            conn.connect()
            gate.wait()
            while (begin := time.monotonic_ns()) < end:
                conn.request("GET", "/data")
                response = conn.getresponse()
                if response.status != 200 or response.read() != BODY:
                    raise RuntimeError("incorrect HTTP response")
                done = time.monotonic_ns()
                if done < end:
                    hist[(done - begin + 999) // 1000] += 1
                    counts[(done-start) // 10**9] += 1
                if period:
                    delay = min(end, begin + period) - done
                    if delay > 0:
                        time.sleep(delay / 1e9)
        except Exception as exc:
            errors.append(repr(exc))
            gate.abort()
        finally:
            conn.close()

    workers = [threading.Thread(target=client, args=pair) for pair in zip(histograms, completions)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    hist = histograms[0] + histograms[1]
    counts = completions[0] + completions[1]
    with args.out.open("x") as out:
        json.dump(dict(start_ns=start, stop_ns=end, requests=sum(hist.values()),
                       errors=errors, rate_per_connection=args.rate,
                       requests_by_second=[counts[i] for i in range(math.ceil(args.seconds))],
                       latency_histogram_us=sorted(hist.items())), out)
        out.write("\n")
    if errors:
        raise SystemExit(str(errors))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("serve")
    client = sub.add_parser("client")
    client.add_argument("port", type=int)
    client.add_argument("seconds", type=float)
    client.add_argument("out", type=Path)
    client.add_argument("--rate", type=float, default=0, help="requests/s per connection, 0 = unlimited")
    client.add_argument("--gate", action="store_true", help="announce readiness and wait for one stdin byte")
    args = parser.parse_args()
    if args.action == "serve":
        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            print(server.server_address[1], flush=True)
            server.serve_forever()
    else:
        if args.seconds <= 0 or args.rate < 0:
            parser.error("seconds must be positive and rate nonnegative")
        measure(args)
