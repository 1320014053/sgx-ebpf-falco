"""Fixed 1 KiB HTTP/1.1 loopback workload, with two persistent connections."""
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
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

    def log_message(self, *unused):
        pass

def serve():
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        print(server.server_address[1], flush=True)
        server.serve_forever()

def measure(port, seconds, out, period=0.0):
    gate = threading.Barrier(3)
    bins = [dict(),dict()]
    failures = []
    started = time.monotonic_ns()
    deadline = started
    def client(index):
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET","/data")
            assert conn.getresponse().read() == BODY
            gate.wait(timeout=10)
            while time.monotonic_ns() < deadline:
                begin = time.monotonic_ns()
                conn.request("GET","/data")
                response = conn.getresponse()
                if response.status != 200 or response.read() != BODY:
                    raise RuntimeError("HTTP response mismatch")
                us = (time.monotonic_ns() - begin + 999) // 1000
                bins[index][us] = bins[index].get(us,0)+1
                if period:
                    remaining = (begin + int(period*1e9) - time.monotonic_ns()) / 1e9
                    if remaining > 0: time.sleep(remaining)
        except Exception as exc:
            failures.append(str(exc))
            gate.abort()
        finally:
            conn.close()
    workers = [threading.Thread(target=client,args=(i,)) for i in range(2)]
    for thread in workers: thread.start()
    while gate.n_waiting < 2 and not gate.broken: time.sleep(.001)
    started = time.monotonic_ns()
    deadline = started + int(seconds * 1e9)
    gate.wait(timeout=10)
    for thread in workers: thread.join()
    stop = time.monotonic_ns()
    hist = bins[0]
    for us,count in bins[1].items(): hist[us] = hist.get(us,0)+count
    out.write_text(json.dumps(dict(start_ns=started,stop_ns=stop,requests=sum(hist.values()),errors=failures,
                                   latency_histogram_us=sorted(hist.items())))+"\n")
    if failures: raise RuntimeError(failures)

if __name__ == "__main__":
    if sys.argv[1] == "serve": serve()
    else: measure(int(sys.argv[2]),float(sys.argv[3]),Path(sys.argv[4]),float(sys.argv[5]) if len(sys.argv)>5 else 0.0)
