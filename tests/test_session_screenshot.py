"""Live MCP screenshot test: configure DROPBEAR_MCP_* and pass SESSION USER."""
import asyncio
import base64
import json
import os
from pathlib import Path
import struct
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
            rejected = await client.call_tool("dropbear_session_screenshot", {
                "session_id": session_id, "expected_user": "dropbear-probe-mismatched-user"})
            assert rejected.isError, rejected
            result = await client.call_tool("dropbear_session_screenshot", {
                "session_id": session_id, "expected_user": user})
            assert not result.isError, result
            metadata = json.loads(result.content[0].text)
            image = result.content[1]
            assert image.type == "image" and image.mimeType == "image/png"
            png = base64.b64decode(image.data, validate=True)
            assert png.startswith(b"\x89PNG\r\n\x1a\n")
            assert struct.unpack(">II", png[16:24]) == (metadata["width"], metadata["height"])
            assert metadata["session_id"] == session_id
            assert metadata["capture_mode"] == "virtual_desktop"
            assert metadata["windows_user"].lower().split("\\")[-1] == user.lower().split("\\")[-1]
            print("PASS live MCP PNG screenshot:", json.dumps(metadata), "bytes=", len(png))


if __name__ == "__main__":
    asyncio.run(main())
