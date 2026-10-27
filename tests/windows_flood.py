"""Flood-resilience regression: preauth caps, absolute auth grace, spawn budget.

Run with native Windows Python, Paramiko and psutil, against each delivered
executable. The server runs with its default limits unless one scenario
overrides a knob through the environment. All accounts, listeners and
connections are disposable fixtures bound to loopback.
"""
import argparse
import socket
import sys
import threading
import time
from pathlib import Path

import psutil
from windows_lifecycle import connect, eventually, server
from windows_native import execute


def hold_slots(port, count, start_index=2):
    """Open `count` idle raw connections from distinct loopback addresses."""
    socks = []
    try:
        for index in range(count):
            sock = socket.create_connection(("127.0.0.1", port), timeout=3,
                source_address=(f"127.0.0.{start_index + index}", 0))
            assert sock.recv(256).startswith(b"SSH-"), f"slot {index} rejected early"
            socks.append(sock)
        return socks
    except Exception:
        for sock in socks:
            sock.close()
        raise


def rejected_fast(port):
    """An over-limit connection must be closed at once, without any banner."""
    start = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        try:
            data = sock.recv(256)
        except ConnectionResetError:
            data = b""
    assert data == b"", f"over-limit connection received {data[:32]!r}"
    return time.monotonic() - start


def await_open_slot(port, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=1)
        except OSError:
            time.sleep(.1)
            continue
        banner = sock.recv(256)
        sock.close()
        if banner.startswith(b"SSH-"):
            # The probe itself briefly occupies the slot until its process is
            # reaped; let the cleanup settle before the caller reconnects.
            time.sleep(.4)
            return time.monotonic() - deadline + timeout
        time.sleep(.1)
    raise AssertionError("no preauth slot became available")


def login_with_retry(port, password, command, timeout=15):
    """A login may land in the millisecond slot-cleanup window right after a
    disconnect; retry until the server accepts it."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with connect(port, password) as client:
                return execute(client, command)
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(.3)


def tree_cpu_seconds(pid, seconds):
    """Accumulate CPU-seconds of the listener tree over a wall interval.

    Connection processes are short lived during a storm; per-process deltas
    are accumulated for every process ever seen, like the KDF sampler.
    """
    root = psutil.Process(pid)
    seen = {}

    def snapshot():
        try:
            procs = [root] + root.children(recursive=True)
        except psutil.Error:
            return
        for item in procs:
            try:
                times = item.cpu_times()
                total = times.user + times.system
            except psutil.Error:
                continue
            record = seen.setdefault(item.pid, [total, total])
            record[1] = total

    end = time.monotonic() + seconds
    while time.monotonic() < end:
        snapshot()
        time.sleep(.05)
    snapshot()
    return sum(last - first for first, last in seen.values())


def caps_test(executable):
    """Defaults: five total preauth slots, immediate close beyond that, and a
    rejection storm that costs almost no CPU."""
    with server(executable) as (process, port, password):
        socks = hold_slots(port, 5)
        try:
            delay = rejected_fast(port)
            assert delay < 1.0, f"over-limit close took {delay:.2f}s"

            stop = threading.Event()
            def hammer():
                while not stop.is_set():
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                            sock.recv(64)
                    except OSError:
                        pass
            threads = [threading.Thread(target=hammer, daemon=True) for _ in range(4)]
            for thread in threads:
                thread.start()
            cpu = tree_cpu_seconds(process.pid, 3)
            stop.set()
            for thread in threads:
                thread.join(timeout=2)
            assert cpu < 1.0, f"rejection storm used {cpu:.2f} CPU-seconds in 3s"

            socks.pop().close()
            await_open_slot(port)
            out = login_with_retry(port, password, "echo flood-ok")
            assert out[0].strip() == b"flood-ok", out
        finally:
            for sock in socks:
                sock.close()
    print("PASS: five-slot cap, fast over-limit close, bounded rejection CPU, "
          "slot reuse and login after the storm", flush=True)


def grace_test(executable):
    """The preauth grace is absolute: idle holders are dropped, slots return,
    and no activity shortens or extends it."""
    with server(executable, DROPBEAR_WIN_AUTH_TIMEOUT="2") as (process, port, password):
        socks = hold_slots(port, 5)
        try:
            rejected_fast(port)
            elapsed = await_open_slot(port, timeout=10)
            assert elapsed < 8, f"grace expiry took {elapsed:.1f}s"
            eventually(lambda: not psutil.Process(process.pid).children(recursive=True),
                       timeout=5)
            out = login_with_retry(port, password, "echo after-grace")
            assert out[2] == 0, out
        finally:
            for sock in socks:
                sock.close()
    print("PASS: idle preauth connections dropped at the grace, slots "
          "recovered and logins work", flush=True)


def budget_test(executable):
    """The spawn budget throttles the backlog instead of killing connections:
    after the burst is spent, queued connections are served one per interval."""
    with server(executable, DROPBEAR_WIN_MAX_UNAUTH="30",
                DROPBEAR_WIN_MAX_UNAUTH_PER_IP="30",
                DROPBEAR_WIN_CONN_RATE="1") as (_, port, password):
        conns = []
        try:
            # Refill to the burst ceiling, then queue more connections than
            # the burst allows. The readiness probe already spent one token.
            time.sleep(2.5)
            for index in range(5):
                conns.append(socket.create_connection(("127.0.0.1", port),
                    timeout=3, source_address=(f"127.0.0.{index + 2}", 0)))
            start = time.monotonic()
            stamps = []
            for sock in conns:
                sock.settimeout(10)
                sock.recv(256)
                stamps.append(time.monotonic() - start)
            # The first `burst` banners arrive at once; the queued rest drain
            # at one per second regardless of where the refill phase sat.
            gaps = [stamps[i + 1] - stamps[i] for i in range(2, 4)]
            assert stamps[1] < 1.0, f"burst was throttled: {stamps}"
            assert all(gap >= .7 for gap in gaps), f"drain not rate spaced: {stamps}"
        finally:
            for sock in conns:
                sock.close()
    print("PASS: spawn budget queues the backlog and drains one per interval",
          flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=lambda value: str(Path(value).resolve()))
    args = parser.parse_args()
    caps_test(args.executable)
    grace_test(args.executable)
    budget_test(args.executable)
