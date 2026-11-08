"""Send a JSON execution request through the native Windows SSH subsystem.

python windows_exec.py --request task.json --port 22 user@host
The optional --input file is passed verbatim as the remote application's stdin.
Authentication and host key handling are performed by the local OpenSSH client.
"""
import argparse
import base64
import json
import struct
import subprocess


def encode_request(request, protocol=2):
    # Binary framing still requires a byte-preserving, non-PTY SSH channel.
    # DBX2 gives each UTF-8 control field a canonical ASCII representation.
    if protocol not in (1, 2):
        raise ValueError("protocol must be 1 or 2")
    fields = bytearray(b"DBX2" if protocol == 2 else b"DBX1")

    def number(value):
        fields.extend(struct.pack(">I", value))

    def string(value):
        if not isinstance(value, str) or "\0" in value:
            raise ValueError("request fields must be strings without NUL")
        data = value.encode("utf-8")
        if protocol == 2:
            data = base64.b64encode(data)
        number(len(data))
        fields.extend(data)

    program = request["program"]
    if not program:
        raise ValueError("program must not be empty")
    string(program)
    string(request.get("cwd", ""))
    env = request.get("env", {})
    args = request.get("args", [])
    if not isinstance(env, dict) or not isinstance(args, list):
        raise ValueError("env must be an object and args must be an array")
    if len(env) > 256 or len(args) > 4096:
        raise ValueError("too many environment variables or arguments")
    number(len(env))
    for name, value in env.items():
        if not name or "=" in name:
            raise ValueError("invalid environment variable name")
        string(name)
        string(value)
    number(len(args))
    for value in args:
        string(value)
    if len(fields) > 1024 * 1024:
        raise ValueError("request exceeds 1 MiB")
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--request", required=True)
    parser.add_argument("--input")
    parser.add_argument("--identity")
    parser.add_argument("--protocol", type=int, choices=(1, 2), default=2,
                        help="wire version (default: 2; use 1 for older servers)")
    opt = parser.parse_args()
    with open(opt.request, encoding="utf-8-sig") as file:
        payload = encode_request(json.load(file), protocol=opt.protocol)
    command = ["ssh", "-T", "-p", str(opt.port)]
    if opt.identity:
        command += ["-i", opt.identity]
    command += ["-s", opt.host, "dropbear-exec-v1"]
    with subprocess.Popen(command, stdin=subprocess.PIPE) as child:
        try:
            child.stdin.write(payload)
            if opt.input:
                with open(opt.input, "rb") as file:
                    while True:
                        data = file.read(65536)
                        if not data:
                            break
                        child.stdin.write(data)
        except BrokenPipeError:
            pass
        finally:
            try:
                child.stdin.close()
            except BrokenPipeError:
                pass
        return child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
