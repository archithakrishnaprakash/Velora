#!/usr/bin/env python3
"""Run the bundled local lab app for practising Velora scans (no internet needed).

    python scripts/run_labapp.py [port]

Then, in another terminal:
    velora scan --target http://127.0.0.1:<port>/ --profile lab \
        --allow-private --operator you --i-am-authorized
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests" / "fixtures"))
from labapp import LabApp  # noqa: E402

if __name__ == "__main__":
    import time
    from http.server import ThreadingHTTPServer
    import labapp
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    srv = ThreadingHTTPServer(("127.0.0.1", port), labapp.Handler)
    print(f"Lab app running at http://127.0.0.1:{port}/  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
