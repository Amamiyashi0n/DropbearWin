"""Live, bounded desktop-token probe: configure DROPBEAR_MCP_*; pass SESSION USER.

Creates one hidden PowerShell probe, which reports its own identity/environment/
window station/desktop and exits after 15 seconds. Removes its unique JSON file.
"""
import base64
import json
from pathlib import Path
import re
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from dropbear_mcp import Remote, Settings
from windows_exec import encode_request


def main():
    session, user = int(sys.argv[1]), sys.argv[2]
    remote = Remote(Settings.from_env())
    context = remote.probe()
    assert context["desktop_launch"]["arbitrary_session"]
    launcher = context["server_executable"]
    powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    def run(program, args):
        return remote.exchange(payload=encode_request({"program": program, "args": args}))

    for value in ("0", "-1", "abc", "4294967295", "99999999999999999999"):
        out, err, code = run(launcher, ["--desktop-launch", "--session", value, powershell])
        assert code != 0 and b"Usage:" in err, (value, out, err, code)
    out, err, code = run(launcher, ["--desktop-launch", "--session", str(session),
        "--expect-user", "dropbear-probe-mismatched-user", powershell])
    assert code != 0 and b"does not match" in err, (out, err, code)

    output = "C:\\Users\\Public\\dropbear-desktop-probe-" + uuid.uuid4().hex + ".json"
    script = r'''
$ErrorActionPreference='Stop'
try {
Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public class DesktopProbe {
 [DllImport("user32.dll")] public static extern IntPtr GetProcessWindowStation();
 [DllImport("user32.dll")] public static extern IntPtr GetThreadDesktop(uint id);
 [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
 [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool GetUserObjectInformationW(IntPtr h, int n, StringBuilder s, int size, out int needed);
 public static string Name(IntPtr h) { int n; var s=new StringBuilder(256); if(!GetUserObjectInformationW(h,2,s,512,out n)) throw new Exception("desktop lookup failed"); return s.ToString(); }
}
'@
$p=[Diagnostics.Process]::GetCurrentProcess()
$result=@{pid=$p.Id;session=$p.SessionId;user=[Security.Principal.WindowsIdentity]::GetCurrent().Name;profile=$env:USERPROFILE;station=[DesktopProbe]::Name([DesktopProbe]::GetProcessWindowStation());desktop=[DesktopProbe]::Name([DesktopProbe]::GetThreadDesktop([DesktopProbe]::GetCurrentThreadId()))}
[IO.File]::WriteAllText('OUTPUT_PATH',($result|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
} catch {
 [IO.File]::WriteAllText('OUTPUT_PATH',(@{error=$_.ToString()}|ConvertTo-Json -Compress))
}
Start-Sleep -Seconds 15
'''.replace("OUTPUT_PATH", output)
    try:
        out, err, code = run(launcher, ["--desktop-launch", "--session", str(session),
            "--expect-user", user, powershell, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
            "-EncodedCommand", base64.b64encode(script.encode("utf-16le")).decode()])
        assert code == 0 and not err, (out, err, code)
        pid = int(re.search(rb"PID (\d+)", out)[1])
        print(out.decode("utf-8"), flush=True)
        # The launching SSH connection is already closed; this process must survive it.
        result = None
        for _ in range(60):
            data, _, status = remote.exchange('type "' + output + '"')
            if status == 0:
                result = json.loads(data)
                break
            time.sleep(.3)
        assert result, "desktop probe did not report within 18 seconds (PID " + str(pid) + ")"
        assert result["pid"] == pid and result["session"] == session, result
        assert result["user"].lower().split("\\")[-1] == user.lower().split("\\")[-1], result
        assert "systemprofile" not in result["profile"].lower() and result["profile"], result
        assert result["station"].lower() == "winsta0" and result["desktop"].lower() == "default", result
        time.sleep(.5)
        check = "Get-Process -Id " + str(pid) + " | Select-Object Id,SessionId | ConvertTo-Json -Compress"
        alive, err, status = run(powershell, ["-NoProfile", "-NonInteractive", "-EncodedCommand",
            base64.b64encode(check.encode("utf-16le")).decode()])
        assert status == 0 and json.loads(alive)["SessionId"] == session, (alive, err, status)
        print("PASS session validation, owner mismatch rejection, desktop token/environment, SSH-independent lifetime")
        print(json.dumps(result, ensure_ascii=False))
    finally:
        remote.exchange('del /f /q "' + output + '"')


if __name__ == "__main__":
    main()
