"""Measure complete SSH command round trips on a persistent loopback connection."""
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time
from windows_lifecycle import server, connect
from windows_native import execute

executable = str(Path(sys.argv[1]).resolve())
report = {"sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(), "cases": {}}
with server(executable) as (_, port, password):
    with connect(port, password) as client:
        for command, expected in (("echo latency", b"latency"), ("exit /b 7", b"")):
            samples = []
            for index in range(35):
                start = time.perf_counter()
                out, err, status = execute(client, command)
                elapsed = (time.perf_counter() - start) * 1000
                assert out.strip() == expected and not err and status == (0 if expected else 7)
                if index >= 5:
                    samples.append(elapsed)
            ordered = sorted(samples)
            report["cases"][command] = {"count": len(samples), "median_ms": statistics.median(samples),
                "p95_ms": ordered[28], "max_ms": max(samples)}
Path(sys.argv[2]).write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report), flush=True)
