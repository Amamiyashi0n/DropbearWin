"""Strict DBX parser regression; run against each native Windows executable."""
import base64
from pathlib import Path
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from windows_exec import encode_request


def number(value):
    return struct.pack(">I", value)


def field(value):
    return number(len(value)) + value


def run(executable):
    # If the final argument is accepted incorrectly, the program prints this marker.
    request = {"program": sys.executable,
               "args": ["-c", "print('UNEXPECTED-EXECUTION')"]}
    invalid = [("magic", b"BAD!")]
    for version in (1, 2):
        magic = f"DBX{version}".encode()
        invalid.extend([
            (f"v{version} missing length", magic),
            (f"v{version} partial length", magic + b"\0\0"),
            (f"v{version} huge length", magic + number(0xffffffff)),
            (f"v{version} header budget", magic + number(1024 * 1024 - 4)),
            (f"v{version} truncated field", magic + number(4) + b"YQ"),
        ])
        # Increment argc and append an invalid last field to an executable request.
        payload = encode_request(request, protocol=version)
        offset = 4
        for _ in range(2):
            offset += 4 + struct.unpack_from(">I", payload, offset)[0]
        offset += 4  # Zero environment entries.
        payload[offset:offset + 4] = number(3)
        invalid.append((f"v{version} missing last argument", bytes(payload)))
        bad = [b"\0", b"a\0b", b"\xff", b"\xc0\xaf", b"\xed\xa0\x80"]
        if version == 2:
            bad = [base64.b64encode(value) for value in bad] + [
                b"A", b"YQ", b"YQ=", b"YQ===", b"Y Q=", b"YQ==\r\n",
                b"=AAA", b"AA=A", b"YQ==YQ==", b"YR==", b"YWJ=",
                b"____", b"----", b"AA\0=", b"!!!!",
            ]
        invalid.extend((f"v{version} bad field {value!r}", bytes(payload) + field(value))
                       for value in bad)
        invalid.append((f"v{version} cumulative budget", bytes(payload) + number(1024 * 1024)))
        # Ensure count limits reject before launching anything.
        prefix = magic + field(base64.b64encode(sys.executable.encode())
                               if version == 2 else sys.executable.encode()) + field(b"")
        invalid.append((f"v{version} env count", prefix + number(257)))
        invalid.append((f"v{version} arg count", prefix + number(0) + number(4097)))

    for label, payload in invalid:
        result = subprocess.run([executable, "--dropbear-win-exec"], input=payload,
                                capture_output=True, timeout=10)
        assert result.returncode == 125 and not result.stdout, (label, result)
        assert b"invalid request" in result.stderr, (label, result)

    # All quartet padding forms, empty fields, and multi-byte UTF-8 remain valid.
    arguments = ["", "a", "ab", "abc", "abcd", "中文😀", "\r\n\t", 'x"\\']
    import json
    for version in (1, 2):
        payload = encode_request({"program": sys.executable, "args": [
            "-c", "import json,sys; print(json.dumps(sys.argv[1:]))", *arguments]},
            protocol=version)
        result = subprocess.run([executable, "--dropbear-win-exec"], input=payload,
                                capture_output=True, timeout=10)
        assert result.returncode == 0 and not result.stderr, result
        assert json.loads(result.stdout) == arguments, result.stdout

    # Count framing is part of the client's 1 MiB wire-header limit.
    empty_size = len(encode_request({"program": "x", "args": [""]}))
    at_limit = "x" * ((1024 * 1024 - empty_size) // 4 * 3)
    assert len(encode_request({"program": "x", "args": [at_limit]})) == 1024 * 1024
    for request in ({"program": "x", "args": [at_limit + "x"]},
                    {"program": "x", "args": ["a\0b"]}):
        try:
            encode_request(request)
        except ValueError:
            pass
        else:
            raise AssertionError("client accepted invalid request")
    print(f"PASS {Path(executable).name}: {len(invalid)} rejected frames, DBX1/DBX2 round trips, client limits")


if __name__ == "__main__":
    run(str(Path(sys.argv[1]).resolve()))
