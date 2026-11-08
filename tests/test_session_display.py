"""Live MCP resolution test; --change tries 1280x720 and restores the original mode."""
import asyncio
import json
import os
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    session_id, user = int(sys.argv[1]), sys.argv[2]
    server = Path(__file__).resolve().parents[1] / "tools" / "dropbear_mcp.py"
    params = StdioServerParameters(command=sys.executable, args=[str(server)], env=dict(os.environ))
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as client:
            await client.initialize()
            base = {"session_id": session_id, "expected_user": user}

            async def call(tool, arguments):
                result = await client.call_tool(tool, arguments)
                assert not result.isError, result
                return json.loads(result.content[0].text)

            before = await call("dropbear_session_display", base)
            assert not before.get("error"), before
            assert before["session_id"] == session_id
            display = next(d for d in before["displays"] if d["primary"])
            mode = display["current"]
            target = dict(base, device=display["device"], width=mode["width"], height=mode["height"])
            tested = await call("dropbear_session_set_resolution", dict(target, test_only=True))
            assert tested["test_code"] == 0 and tested["applied"] is False, tested
            invalid = await client.call_tool("dropbear_session_set_resolution", dict(target, width=1))
            assert invalid.isError, invalid
            mismatch = await client.call_tool("dropbear_session_display", dict(base, expected_user="dropbear-wrong-user"))
            assert mismatch.isError, mismatch
            if "--change" in sys.argv:
                try:
                    changed = await call("dropbear_session_set_resolution", dict(target, width=1280, height=720))
                    if changed.get("applied"):
                        assert changed["verified"] and changed["after"]["width"] == 1280 and changed["after"]["height"] == 720
                    else:
                        assert changed.get("error") and changed.get("status") == "client_resize_required", changed
                    print("CHANGE:", json.dumps(changed), flush=True)
                finally:
                    restored = await call("dropbear_session_set_resolution", target)
                    assert restored.get("applied") and restored.get("verified"), restored
                    print("RESTORE:", json.dumps(restored), flush=True)
            after = await call("dropbear_session_display", base)
            actual = next(d["current"] for d in after["displays"] if d["device"] == display["device"])
            assert actual["width"] == mode["width"] and actual["height"] == mode["height"], after
            print("PASS live display query, mode test, validation, identity guard and verified result handling")


if __name__ == "__main__":
    asyncio.run(main())
