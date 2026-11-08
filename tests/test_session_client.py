"""Selection, preflight and identity invariants independent of a live desktop."""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from session_client import SessionRemote, select_session, validate_work


class SessionSelection(unittest.TestCase):
    def setUp(self):
        self.rows = [{"session_id": 0, "username": "", "windows_user": "", "selectable": False},
                     {"session_id": 2, "username": "amamiya", "windows_user": "HOST\\amamiya", "sid": "sid2", "selectable": True},
                     {"session_id": 3, "username": "agent", "windows_user": "HOST\\agent", "sid": "sid3", "selectable": True},
                     {"session_id": 4, "username": "offline", "windows_user": "HOST\\offline", "selectable": False}]

    def test_explicit_and_username_owner_selection(self):
        self.assertEqual(select_session(self.rows, None, "AGENT")["session_id"], 3)
        self.assertEqual(select_session(self.rows, 3, "host\\agent")["sid"], "sid3")
        with self.assertRaises(ValueError): select_session(self.rows, 2, "agent")
        with self.assertRaises(ValueError): select_session(self.rows, None, None)

    def test_ambiguity_never_chooses_first(self):
        self.rows.append(dict(self.rows[2], session_id=5))
        with self.assertRaisesRegex(ValueError, "multiple sessions"):
            select_session(self.rows, None, "agent")
        self.assertEqual(select_session(self.rows, 5, "agent")["session_id"], 5)

    def test_zero_and_disconnected_rejected(self):
        for session in (0, 4, -1, True):
            with self.assertRaises(ValueError): select_session(self.rows, session, None)

    def test_request_preflight(self):
        for program in ("node.exe", r"\node.exe", "C:node.exe", "C:\\node\0.exe"):
            with self.assertRaises(ValueError): validate_work("exec", {"program": program}, 10)
        self.assertEqual(validate_work("exec", {"program": r"C:\node.exe", "args": ["a b", '"quoted"', "中文"]}, 10)["timeout"], 10)
        with self.assertRaises(ValueError): validate_work("exec", {"program": r"C:\node.exe", "env": {"a=b": "x"}}, 10)
        with self.assertRaises(ValueError): validate_work("exec", {"program": r"C:\node.exe", "stdin_base64": "@@"}, 10)

    def test_ui_requires_window_and_coordinates(self):
        with self.assertRaises(ValueError): validate_work("ui", {"action": "text", "text": "hello"}, 10)
        with self.assertRaises(ValueError): validate_work("ui", {"action": "click", "window_id": "12", "x": None, "y": 0}, 10)
        with self.assertRaises(ValueError): validate_work("ui", {"action": "text", "window_id": "12", "text": "a"*4097}, 10)
        self.assertEqual(validate_work("ui", {"action": "click", "window_id": "12", "x": -100, "y": 0}, 10)["button"], "left")

    def test_identity_and_worker_path_guards(self):
        with self.assertRaises(RuntimeError): SessionRemote._check_identity({"session_id": 3, "sid": "other"}, self.rows[2])
        with self.assertRaises(ValueError): SessionRemote._worker_path("C:/ProgramData/DropbearWin", "../other")

    def test_invalid_request_does_not_start_worker(self):
        remote = SessionRemote()
        remote.session_worker_start = Mock()
        with self.assertRaises(ValueError): remote.session_action("exec", {"program": "relative.exe"}, username="agent")
        remote.session_worker_start.assert_not_called()

    def test_cleanup_failure_does_not_hide_execution_result(self):
        remote = SessionRemote()
        remote.session_worker_start = Mock(return_value={"worker_id": "a"*32})
        remote.session_worker_call = Mock(return_value={"execution": {"exit_code": 7}})
        remote.session_worker_stop = Mock(side_effect=RuntimeError("busy"))
        result = remote.session_action("context", {}, username="agent")
        self.assertEqual(result["execution"]["exit_code"], 7)
        self.assertEqual(result["worker_cleanup"]["worker_id"], "a"*32)


if __name__ == "__main__": unittest.main()
