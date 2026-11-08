"""Live session worker regression; credentials via DROPBEAR_MCP_*.

Pass SESSION USER, optionally --node-exe C:\absolute\node.exe and --ui.
The UI test opens, types into, clicks and closes only its unique disposable form.
It never changes an existing application or logs a user in/out.
"""
import argparse
import base64
import json
from pathlib import Path
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from dropbear_mcp import Remote, Settings
from windows_exec import encode_request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session", type=int)
    parser.add_argument("user")
    parser.add_argument("--node-exe")
    parser.add_argument("--ui", action="store_true")
    args = parser.parse_args()
    remote = Remote(Settings.from_env())
    rows = remote.session_list()["sessions"]
    selected = remote.session_resolve(args.session, args.user)
    assert selected["selectable"]
    try:
        remote.session_resolve(args.session, "dropbear-probe-wrong-user")
    except ValueError:
        pass
    else:
        raise AssertionError("Mismatched owner was accepted")
    worker = remote.session_worker_start(args.session, args.user, idle_timeout=120)
    worker_id = worker["worker_id"]
    client = remote.connect()
    ui_path = worker["directory"] + "/ui-test.json"
    ui_window = None
    try:
        context = remote.session_worker_call(worker_id, "context")
        assert context["session_id"] == args.session and context["sid"] == selected["sid"]
        assert context["userprofile"].lower().endswith("\\" + args.user.lower())
        result = remote.session_worker_call(worker_id, "exec", {"program": r"C:\Windows\System32\cmd.exe",
            "args": ["/d", "/s", "/c", "echo %USERNAME% & echo %DBTEST% & cd & exit /b 7"],
            "cwd": context["userprofile"], "env": {"DBTEST": "session-env-ok"}})
        output = base64.b64decode(result["execution"]["stdout_base64"])
        assert result["execution"]["exit_code"] == 7 and b"session-env-ok" in output
        assert args.user.lower().encode() in output.lower()
        for code, expected in (("$global:dbCounter=41; ++$global:dbCounter; $global:dbCounter", 42),
                               ("++$global:dbCounter; $global:dbCounter", 43)):
            value = remote.session_worker_call(worker_id, "powershell", {"code": code})
            assert value["values"] == [expected], value
        timed = remote.session_worker_call(worker_id, "exec", {
            "program": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "args": ["-NoProfile", "-Command", "Start-Sleep -Seconds 20"]}, timeout=1)
        assert timed["execution"]["timed_out"] and timed["execution"]["exit_code"] == -1, timed
        # The worker must remain usable after killing the command job.
        assert remote.session_worker_call(worker_id, "context")["pid"] == context["pid"]
        print("PASS worker identity/profile/env/cwd, nonzero exit, persistent state, timeout containment", flush=True)
        if args.node_exe:
            payload = bytes(range(256)) * 1024
            argv = ["", "space separated", 'quoted"value', "中文", "trailing slash\\", "&literal"]
            script = "const fs=require('fs');process.stdout.write(JSON.stringify({args:process.argv.slice(1),user:process.env.USERNAME,cwd:process.cwd(),input:fs.readFileSync(0).toString('base64')}));process.exitCode=7;"
            node = remote.session_worker_call(worker_id, "exec", {"program": args.node_exe,
                "args": ["-e", script, "--", *argv], "cwd": context["userprofile"],
                "stdin_base64": base64.b64encode(payload).decode()})
            actual = json.loads(base64.b64decode(node["execution"]["stdout_base64"]))
            assert node["execution"]["exit_code"] == 7 and actual["args"] == argv, node
            assert actual["user"].casefold() == args.user.casefold() and actual["cwd"] == context["userprofile"]
            assert base64.b64decode(actual["input"]) == payload
            limited = remote.session_worker_call(worker_id, "exec", {"program": args.node_exe,
                "args": ["-e", "process.stdout.write(Buffer.alloc(2*1024*1024));setInterval(()=>{},1000)"]})
            assert limited["execution"]["output_limit_exceeded"], limited
            assert len(base64.b64decode(limited["execution"]["stdout_base64"])) <= 1024 * 1024
            print("PASS real Node argv/Unicode/binary stdin, selected-user environment", flush=True)
        if args.ui:
            title = "DropbearWin UI probe " + uuid.uuid4().hex
            path = ui_path.replace("/", "\\")
            script = r'''
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$f=New-Object Windows.Forms.Form
$f.Text='TITLE';$f.StartPosition='Manual';$f.Location=New-Object Drawing.Point(140,140);$f.Size=New-Object Drawing.Size(500,240)
$t=New-Object Windows.Forms.TextBox;$t.Location=New-Object Drawing.Point(20,20);$t.Width=400
$b=New-Object Windows.Forms.Button;$b.Text='Probe';$b.Location=New-Object Drawing.Point(20,80);$b.Size=New-Object Drawing.Size(140,35)
$f.Controls.Add($t);$f.Controls.Add($b);$script:clicked=$false
function Save { $p=$b.PointToScreen((New-Object Drawing.Point(10,10))); [IO.File]::WriteAllText('OUTPUT.tmp',(@{text=$t.Text;selection=$t.SelectionLength;events=@($script:events);last_key=$script:lastKey;control=$script:control;clicked=$script:clicked;x=$p.X;y=$p.Y;pid=$PID}|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false))); Move-Item -LiteralPath 'OUTPUT.tmp' -Destination 'OUTPUT' -Force }
$t.Add_TextChanged({Save});$b.Add_Click({$script:clicked=$true;Save})
$t.Add_KeyDown({$script:events+=@((''+$_.KeyCode+':'+$_.Control));if($_.Control -and $_.KeyCode -eq [Windows.Forms.Keys]::A){$t.SelectAll();$_.SuppressKeyPress=$true};Save})
$t.Add_KeyUp({$script:lastKey=$_.KeyCode.ToString();$script:control=$_.Control;Save})
$f.Add_Shown({$f.Activate();$t.Focus();Save})
$timer=New-Object Windows.Forms.Timer;$timer.Interval=90000;$timer.Add_Tick({$f.Close()});$timer.Start()
try {$null=$f.ShowDialog()}finally{$timer.Dispose();$f.Dispose()}
'''.replace("TITLE", title).replace("OUTPUT", path)
            encoded = base64.b64encode(script.encode("utf-16le")).decode()
            ctx = remote.probe()
            out, err, status = remote.exchange(payload=encode_request({"program": ctx["server_executable"], "args": [
                "--desktop-launch", "--session", str(args.session), "--expect-user", args.user,
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", encoded]}))
            assert status == 0, (out, err)
            for _ in range(25):
                windows = remote.session_worker_call(worker_id, "ui", {"action": "windows"})["result"]
                matches = [w for w in windows if w["title"] == title]
                if matches:
                    ui_window = matches[0]["window_id"]
                    break
                time.sleep(.2)
            assert ui_window, "Disposable form did not appear in the selected session"
            remote.session_worker_call(worker_id, "ui", {"action": "focus", "window_id": ui_window})
            remote.session_worker_call(worker_id, "ui", {"action": "text", "window_id": ui_window, "text": "discard"})
            remote.session_worker_call(worker_id, "ui", {"action": "keys", "window_id": ui_window, "keys": ["CTRL", "A"]})
            time.sleep(.2)
            with client.open_sftp() as sftp:
                selected_text = remote._read_worker_json(sftp, ui_path)
            assert selected_text["selection"] == len("discard"), selected_text
            assert "A:True" in selected_text["events"], selected_text
            expected_text = "Dropbear session 交互 verified"
            remote.session_worker_call(worker_id, "ui", {"action": "text", "window_id": ui_window, "text": expected_text})
            with client.open_sftp() as sftp:
                state = remote._read_worker_json(sftp, ui_path)
            assert state["text"] == expected_text, state
            remote.session_worker_call(worker_id, "ui", {"action": "click", "window_id": ui_window, "x": state["x"], "y": state["y"]})
            time.sleep(.2)
            with client.open_sftp() as sftp:
                state = remote._read_worker_json(sftp, ui_path)
            assert state["clicked"], state
            print("PASS actual UI focus, Unicode text, CTRL+A and mouse click on disposable form", flush=True)
    finally:
        if ui_window:
            remote.session_worker_call(worker_id, "ui", {"action": "keys", "window_id": ui_window, "keys": ["ALT", "F4"]})
            time.sleep(.2)
        with client.open_sftp() as sftp:
            try: sftp.remove(ui_path)
            except FileNotFoundError: pass
        client.close()
        remote.session_worker_stop(worker_id)
        print("PASS worker stopped and queue cleaned", flush=True)


if __name__ == "__main__": main()
