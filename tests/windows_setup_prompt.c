/* Console/SCM fixture for the real EXE. Refuses an existing DropbearWin service.
 * Arguments: EXE PORT SERVICE_BINARY|- EXPECTED_PROMPT|- ANSWER(n|y)
 * Run only in a disposable Windows/Wine environment. */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static BOOL WINAPI ignore_control(DWORD control) { (void)control; return TRUE; }

static void type_text(HANDLE input, const wchar_t *value) {
    INPUT_RECORD events[256];
    DWORD n = 0, written;
    while (*value && n + 2 < 256) {
        INPUT_RECORD event;
        memset(&event, 0, sizeof(event));
        event.EventType = KEY_EVENT;
        event.Event.KeyEvent.bKeyDown = TRUE;
        event.Event.KeyEvent.wRepeatCount = 1;
        event.Event.KeyEvent.wVirtualKeyCode = *value == L'\r' ? VK_RETURN : (VkKeyScanW(*value) & 255);
        event.Event.KeyEvent.uChar.UnicodeChar = *value++;
        events[n++] = event;
        event.Event.KeyEvent.bKeyDown = FALSE;
        events[n++] = event;
    }
    WriteConsoleInputW(input, events, n, &written);
}

static void snapshot(HANDLE console, char *text, DWORD size) {
    CONSOLE_SCREEN_BUFFER_INFO info;
    COORD origin = {0, 0};
    DWORD length, read = 0;
    *text = 0;
    if (!GetConsoleScreenBufferInfo(console, &info)) return;
    length = info.dwSize.X * (info.dwCursorPosition.Y + 1);
    if (length >= size) length = size - 1;
    if (ReadConsoleOutputCharacterA(console, text, length, origin, &read)) text[read] = 0;
}

int wmain(int argc, wchar_t **argv) {
    SC_HANDLE manager = NULL, service = NULL, existing;
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    HANDLE output = NULL, input = INVALID_HANDLE_VALUE, console = INVALID_HANDLE_VALUE;
    STARTUPINFOW startup;
    PROCESS_INFORMATION child;
    SERVICE_STATUS status;
    wchar_t command[4096], service_command[4096];
    char text[65536], expected[256];
    DWORD written, code = 1;
    int result = 1, started = 0, answered = 0, username = 0, password = 0, confirm = 0, i;
    int want_prompt;
    if (argc != 6) return 2;
    want_prompt = wcscmp(argv[4], L"-") != 0;
    WideCharToMultiByte(CP_UTF8, 0, argv[4], -1, expected, sizeof(expected), NULL, NULL);
    DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_OUTPUT_HANDLE), GetCurrentProcess(),
        &output, 0, FALSE, DUPLICATE_SAME_ACCESS);
    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!manager) goto done;
    existing = OpenServiceW(manager, L"DropbearWin", SERVICE_QUERY_CONFIG);
    if (existing) { CloseServiceHandle(existing); result = 77; goto done; }
    if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) goto done;
    if (wcscmp(argv[3], L"-")) {
        _snwprintf(service_command, 4096, L"\"%ls\" --service DropbearWin", argv[3]);
        service = CreateServiceW(manager, L"DropbearWin", L"Setup prompt fixture", SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            service_command, NULL, NULL, NULL, NULL, NULL);
        if (!service) goto done;
    }
    FreeConsole();
    if (!AllocConsole()) goto done;
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    SetConsoleCtrlHandler(ignore_control, TRUE);
    input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, NULL);
    console = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, NULL);
    if (input == INVALID_HANDLE_VALUE || console == INVALID_HANDLE_VALUE) goto done;
    {
        COORD size = {180, 300};
        SetConsoleScreenBufferSize(console, size);
    }
    memset(&startup, 0, sizeof(startup)); memset(&child, 0, sizeof(child));
    startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input; startup.hStdOutput = console; startup.hStdError = console;
    _snwprintf(command, 4096, L"\"%ls\" -p 127.0.0.1:%ls", argv[1], argv[2]);
    if (!CreateProcessW(argv[1], command, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP,
            NULL, NULL, &startup, &child)) goto done;
    started = 1;
    for (i = 0; i < 400; i++) {
        snapshot(console, text, sizeof(text));
        if (!username && strstr(text, "SSH username:")) { type_text(input, L"setup-fixture\r"); username = 1; }
        if (!password && strstr(text, "SSH password:")) { type_text(input, L"fixture-only-password\r"); password = 1; }
        if (!confirm && strstr(text, "Confirm password:")) { type_text(input, L"fixture-only-password\r"); confirm = 1; }
        if (!answered && strstr(text, "[y/N]")) {
            type_text(input, argv[5][0] == L'y' ? L"y\r" : L"n\r");
            answered = 1;
        }
        if (strstr(text, "Status:") && strstr(text, "RUNNING")) break;
        if (WaitForSingleObject(child.hProcess, 0) == WAIT_OBJECT_0) break;
        Sleep(50);
    }
    snapshot(console, text, sizeof(text));
    if (output) WriteFile(output, text, (DWORD)strlen(text), &written, NULL);
    if (want_prompt) {
        if (!answered || !strstr(text, expected)) goto done;
    } else if (answered || strstr(text, "[y/N]")) goto done;
    if (argv[5][0] == L'y') {
        if (WaitForSingleObject(child.hProcess, 5000) != WAIT_OBJECT_0 ||
                !GetExitCodeProcess(child.hProcess, &code) || code != 0 ||
                !strstr(text, "Service installed:") || !strstr(text, "Program Files\\DropbearWin")) goto done;
    } else if (!strstr(text, "RUNNING")) goto done;
    result = 0;
done:
    if (started) {
        if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0) {
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.dwProcessId);
            if (WaitForSingleObject(child.hProcess, 4000) != WAIT_OBJECT_0) TerminateProcess(child.hProcess, 1);
        }
        WaitForSingleObject(child.hProcess, 3000);
        CloseHandle(child.hThread); CloseHandle(child.hProcess);
    }
    if (!service && started && argv[5][0] == L'y')
        service = OpenServiceW(manager, L"DropbearWin", SERVICE_ALL_ACCESS);
    if (service) {
        for (i = 0; i < 100; i++) {
            if (!QueryServiceStatus(service, &status) || status.dwCurrentState == SERVICE_STOPPED) break;
            ControlService(service, SERVICE_CONTROL_STOP, &status); Sleep(100);
        }
        DeleteService(service); CloseServiceHandle(service);
    }
    if (manager) CloseServiceHandle(manager);
    if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
    if (console != INVALID_HANDLE_VALUE) CloseHandle(console);
    if (output) CloseHandle(output);
    return result;
}
