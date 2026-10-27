"""Bounded loopback stress test; requires native Windows Python, Paramiko, psutil."""
import concurrent.futures
import hashlib
import json
import logging
import os
from pathlib import Path
import platform
import statistics
import sys
import threading
import time

import psutil
from windows_lifecycle import server, connect, preauth_test
from windows_native import execute

logging.getLogger("paramiko").setLevel(logging.CRITICAL)


def run(executable, destination):
    started = time.monotonic()
    report = {"binary": executable, "sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
              "host": platform.platform(), "logical_cpus": os.cpu_count(),
              "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "phases": [], "errors": []}
    observed = {}
    samples = []
    stop = threading.Event()
    def measure(root):
        while not stop.is_set():
            try:
                processes = [root] + root.children(recursive=True)
                rss = handles = 0
                for process in processes:
                    try:
                        observed[(process.pid, process.create_time())] = process
                        rss += process.memory_info().rss
                        handles += process.num_handles()
                    except psutil.Error:
                        pass
                samples.append({"rss_mib": rss / 1048576, "handles": handles,
                                "processes": len(processes)})
            except psutil.Error:
                pass
            stop.wait(.25)
    def phase(name, workers, work, count):
        latencies = []
        errors = []
        begin = time.monotonic()
        def timed(index):
            tick = time.monotonic()
            try:
                work(index)
                return time.monotonic() - tick, None
            except Exception as error:
                return time.monotonic() - tick, repr(error)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for latency, error in pool.map(timed, range(count)):
                latencies.append(latency)
                if error:
                    errors.append(error)
        ordered = sorted(latencies)
        result = {"name": name, "workers": workers, "attempts": count,
                  "success": count - len(errors), "errors": errors,
                  "seconds": round(time.monotonic() - begin, 3),
                  "p50_ms": round(statistics.median(ordered) * 1000, 1),
                  "p95_ms": round(ordered[min(len(ordered)-1, int(len(ordered)*.95))] * 1000, 1),
                  "max_ms": round(max(ordered) * 1000, 1)}
        report["phases"].append(result)
        report["errors"].extend(errors)
        print(json.dumps(result), flush=True)
    try:
        with server(executable) as (listener, port, password):
            root = psutil.Process(listener.pid)
            report["listener_baseline"] = {"rss_mib": root.memory_info().rss / 1048576,
                                            "handles": root.num_handles()}
            monitor = threading.Thread(target=measure, args=(root,), daemon=True)
            monitor.start()
            clients = []
            try:
                for concurrency in (4, 12, 24):
                    # Authenticate serially to distinguish authenticated load
                    # from the intentional five-preauth-per-IP admission limit.
                    while len(clients) < concurrency:
                        clients.append(connect(port, password))
                        time.sleep(.05)
                    def command(index):
                        client = clients[index]
                        for sequence in range(10):
                            marker = f"stress-{index}-{sequence}"
                            out, err, status = execute(client, "echo " + marker)
                            assert out.strip() == marker.encode() and not err and status == 0
                    phase(f"exec_10_per_client_{concurrency}", concurrency, command, concurrency)
                    def welcome(index):
                        for _ in range(2):
                            channel = clients[index].get_transport().open_session(timeout=15)
                            channel.settimeout(15)
                            try:
                                channel.get_pty()
                                channel.invoke_shell()
                                output = b""
                                while b"Raw mode:" not in output:
                                    chunk = channel.recv(4096)
                                    assert chunk and len(output) < 16384
                                    output += chunk
                                assert b"Welcome to Dropbear" in output and b"Memory:" in output and b"CPU:" in output
                            finally:
                                channel.close()
                    phase(f"welcome_2_per_client_{concurrency}", concurrency, welcome, concurrency)
                data = bytes(range(256)) * 4096
                def transfer(index):
                    # Each SSH connection has the test's isolated data path.
                    with clients[index].open_sftp() as sftp:
                        remote = str(Path(root.environ()["DROPBEAR_WIN_DATA_DIR"]) / f"load-{index}.bin").replace("\\", "/")
                        try:
                            with sftp.file(remote, "wb") as stream:
                                stream.write(data)
                            with sftp.file(remote, "rb") as stream:
                                assert stream.read() == data, "file integrity mismatch"
                        finally:
                            sftp.remove(remote)
                phase("sftp_1MiB_upload_and_download", 24, transfer, 24)
            finally:
                for client in clients:
                    client.close()
            def churn(index):
                with connect(port, password) as client:
                    out, err, status = execute(client, "echo reconnect")
                    assert out.strip() == b"reconnect" and not err and status == 0
            time.sleep(2)
            phase("login_exec_disconnect", 4, churn, 100)
            time.sleep(3)
            report["listener_after"] = {"rss_mib": root.memory_info().rss / 1048576,
                                        "handles": root.num_handles(),
                                        "children": len(root.children(recursive=True))}
            assert report["listener_after"]["children"] == 0, "children remain after quiescence"
            with connect(port, password) as client:
                assert execute(client, "echo healthy")[0].strip() == b"healthy"
        time.sleep(2)
        survivors = []
        for process in observed.values():
            try:
                if process.is_running():
                    survivors.append(process.pid)
            except psutil.Error:
                pass
        report["surviving_observed_pids"] = survivors
        assert not survivors, survivors
        preauth_test(executable)
        report["preauth_limits"] = "passed per-IP 5 and total 30, including slot release"
    except Exception as error:
        report["errors"].append(repr(error))
        raise
    finally:
        stop.set()
        if "monitor" in locals():
            monitor.join(timeout=3)
        report["peak_tree"] = {key: max((sample[key] for sample in samples), default=0)
                               for key in ("rss_mib", "handles", "processes")}
        report["duration_seconds"] = round(time.monotonic() - started, 2)
        report["passed"] = not report["errors"]
        Path(destination).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print("REPORT", destination, "PASS" if report["passed"] else "FAIL", flush=True)
    return report["passed"]


if __name__ == "__main__":
    sys.exit(0 if run(str(Path(sys.argv[1]).resolve()), sys.argv[2]) else 1)
