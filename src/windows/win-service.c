/* Dropbear-win host lifecycle. Uses APIs available on Windows XP. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include "win-account.h"
#include "win-agent-bundle.h"
#include <shellapi.h>
#include <sddl.h>

extern int dropbear_main(int argc, char **argv, const char *multipath);
static SERVICE_STATUS_HANDLE service_handle;
static SERVICE_STATUS service_status;
static volatile LONG stop_requested;
static HANDLE listener_stopped;
static int service_mode;
static int server_argc;
static char **server_argv;
static WCHAR service_name[256];

static void report_status(DWORD state, DWORD error) {
	if (!service_handle) return;
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	service_status.dwCurrentState = state;
	service_status.dwControlsAccepted = state == SERVICE_RUNNING
		? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
	service_status.dwWin32ExitCode = error ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
	service_status.dwServiceSpecificExitCode = error;
	service_status.dwCheckPoint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 1 : 0;
	service_status.dwWaitHint = service_status.dwCheckPoint ? 10000 : 0;
	SetServiceStatus(service_handle, &service_status);
}

static DWORD WINAPI control_service(DWORD control, DWORD event, LPVOID data, LPVOID context) {
	(void)event; (void)data; (void)context;
	if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
		InterlockedExchange(&stop_requested, 1);
		/* The listener thread owns all status transitions and resource cleanup. */
		return NO_ERROR;
	}
	if (control == SERVICE_CONTROL_INTERROGATE) return NO_ERROR;
	return ERROR_CALL_NOT_IMPLEMENTED;
}

static BOOL WINAPI control_console(DWORD control) {
	if (control != CTRL_C_EVENT && control != CTRL_BREAK_EVENT &&
		control != CTRL_CLOSE_EVENT && control != CTRL_SHUTDOWN_EVENT) return FALSE;
	InterlockedExchange(&stop_requested, 1);
	/* Returning from CTRL_CLOSE immediately lets Windows kill the process
	 * before the listener has removed its pidfile and reclaimed children. */
	if ((control == CTRL_CLOSE_EVENT || control == CTRL_SHUTDOWN_EVENT) && listener_stopped)
		WaitForSingleObject(listener_stopped, 4000);
	return TRUE;
}

int dropbear_win_is_service(void) { return service_mode; }
int dropbear_win_listener_init(void) {
	listener_stopped = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!listener_stopped) return 0;
	if (service_mode) return 1;
	/* Launchers may pass on the console's inherited ignore-Ctrl+C attribute. */
	return SetConsoleCtrlHandler(NULL, FALSE) && SetConsoleCtrlHandler(control_console, TRUE);
}
int dropbear_win_stop_requested(void) {
	if (!InterlockedCompareExchange(&stop_requested, 0, 0)) return 0;
	if (service_handle && service_status.dwCurrentState != SERVICE_STOP_PENDING)
		report_status(SERVICE_STOP_PENDING, 0);
	return 1;
}
void dropbear_win_listener_ready(void) {
	if (!dropbear_win_stop_requested()) report_status(SERVICE_RUNNING, 0);
}
void dropbear_win_service_stopped(int code) {
	if (listener_stopped) SetEvent(listener_stopped);
	report_status(SERVICE_STOPPED, (DWORD)code);
}

static void WINAPI service_entry(DWORD argc, LPWSTR *argv) {
	WCHAR executable[32768], *slash;
	char log_path[MAX_PATH];
	int result;
	(void)argc; (void)argv;
	service_handle = RegisterServiceCtrlHandlerExW(service_name, control_service, NULL);
	if (!service_handle) return;
	report_status(SERVICE_START_PENDING, 0);
	/* SCM normally starts in System32; relative deployment paths use exe dir. */
	if (GetModuleFileNameW(NULL, executable, 32768)) {
		slash = wcsrchr(executable, L'\\');
		if (slash) { *slash = 0; SetCurrentDirectoryW(executable); }
	}
	if (snprintf(log_path, sizeof(log_path), "%s\\service.log", dropbear_win_data_dir())
		>= (int)sizeof(log_path) || !freopen(log_path, "ab", stderr)) {
		dropbear_win_service_stopped(1);
		return;
	}
	setvbuf(stderr, NULL, _IONBF, 0);
	_dup2(_fileno(stderr), _fileno(stdout));
	freopen("NUL", "rb", stdin);
	SetStdHandle(STD_ERROR_HANDLE, (HANDLE)_get_osfhandle(_fileno(stderr)));
	SetStdHandle(STD_OUTPUT_HANDLE, (HANDLE)_get_osfhandle(_fileno(stdout)));
	SetStdHandle(STD_INPUT_HANDLE, (HANDLE)_get_osfhandle(_fileno(stdin)));
	SetHandleInformation(GetStdHandle(STD_ERROR_HANDLE), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	SetHandleInformation(GetStdHandle(STD_OUTPUT_HANDLE), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	SetHandleInformation(GetStdHandle(STD_INPUT_HANDLE), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
	result = dropbear_main(server_argc, server_argv, NULL);
	dropbear_win_process_cleanup();
	dropbear_win_service_stopped(result);
}

int dropbear_win_service_main(int argc, char **argv) {
	SERVICE_TABLE_ENTRYW table[2];
	if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[2], -1,
		service_name, sizeof(service_name) / sizeof(service_name[0]))) return 1;
	service_mode = 1;
	server_argc = argc - 2;
	server_argv = argv + 2;
	server_argv[0] = argv[0];
	memset(table, 0, sizeof(table));
	table[0].lpServiceName = service_name;
	table[0].lpServiceProc = service_entry;
	if (!StartServiceCtrlDispatcherW(table)) {
		fprintf(stderr, "Service dispatcher failed: Windows error %lu. Start --service through SCM.\n",
			(unsigned long)GetLastError());
		return 1;
	}
	return 0;
}

/* Zero-parameter deployment asks whether to migrate the portable copy into
 * Program Files/ProgramData and register an automatic Windows service. */
#define WIN_SETUP_NAME L"DropbearWin"
#define WIN_SETUP_DISPLAY L"Dropbear for Windows"
#define WIN_SETUP_SCRIPT L"uninstall-dropbear-service.cmd"

static void write_uninstall_script(const wchar_t *executable) {
	wchar_t directory[32768], *slash, *name;
	wchar_t path[MAX_PATH];
	char script[1024], program[MAX_PATH];
	FILE *file;
	int written, i;
	if (wcslen(executable) >= 32768) return;
	wcscpy(directory, executable);
	slash = wcsrchr(directory, L'\\');
	if (!slash) return;
	name = slash + 1;
	if (!*name || !WideCharToMultiByte(CP_ACP, 0, name, -1,
			program, sizeof(program), NULL, NULL)) return;
	/* Batch expansion would reinterpret these characters as commands or
	 * variables. The CLI remains available for unusual EXE names. */
	for (i = 0; program[i]; i++)
		if (!((program[i] >= 'a' && program[i] <= 'z') ||
				(program[i] >= 'A' && program[i] <= 'Z') ||
				(program[i] >= '0' && program[i] <= '9') ||
				program[i] == '.' || program[i] == '_' || program[i] == '-')) return;
	*slash = 0;
	written = _snwprintf(path, MAX_PATH, L"%ls\\%ls", directory, WIN_SETUP_SCRIPT);
	if (written <= 0 || written >= MAX_PATH) return;
	written = snprintf(script, sizeof(script),
		"@echo off\r\n"
		"\"%%~dp0%s\" --uninstall %%*\r\n"
		"set \"dropbear_uninstall_result=%%errorlevel%%\"\r\n"
		"pause\r\n"
		"exit /b %%dropbear_uninstall_result%%\r\n", program);
	if (written <= 0 || written >= (int)sizeof(script)) return;
	file = _wfopen(path, L"wb");
	if (!file) {
		fprintf(stderr, "Could not write the uninstall script (Windows error %lu).\n",
			(unsigned long)GetLastError());
		return;
	}
	fwrite(script, 1, written, file);
	fclose(file);
	printf("Uninstall script: %ls\n", path);
}

/* Answers only from a real keypress; an EOF or closed pipe means "no". */
static int read_yes_answer(void) {
	int c, answer = 0;
	while ((c = fgetc(stdin)) != EOF && c != '\n') {
		if (!answer && c != ' ' && c != '\t' && c != '\r') answer = c;
	}
	return answer == 'y' || answer == 'Y';
}

static int open_existing_service(DWORD access, SC_HANDLE *service_out) {
	SC_HANDLE manager, service;
	manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!manager) return 0;
	service = OpenServiceW(manager, WIN_SETUP_NAME, access);
	CloseServiceHandle(manager);
	if (!service) return 0;
	*service_out = service;
	return 1;
}

static int current_process_is_administrator(void) {
	SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
	PSID administrators = NULL;
	BOOL member = FALSE;
	BOOL checked;
	if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) return 0;
	checked = CheckTokenMembership(NULL, administrators, &member);
	FreeSid(administrators);
	return checked && member;
}

/* Load shell32 only for the installer. A normal server or minimal WinPE image
 * does not gain a new DLL dependency just to support UAC on desktop Windows. */
static int request_autostart_elevation(int argc, char **argv) {
	typedef BOOL (WINAPI *shell_execute_ex_fn)(SHELLEXECUTEINFOW *);
	WCHAR executable[32768];
	wchar_t *parameters;
	HMODULE shell;
	shell_execute_ex_fn shell_execute;
	SHELLEXECUTEINFOW request;
	DWORD length, wait_result, exit_code = 1;
	int result = 1;
	length = GetModuleFileNameW(NULL, executable, 32768);
	parameters = dropbear_win_build_autostart_relaunch_parameters(argc, argv);
	if (!length || length >= 32768 || !parameters) {
		fputs("Could not prepare the administrator request.\n", stderr);
		if (parameters) HeapFree(GetProcessHeap(), 0, parameters);
		return 1;
	}
	shell = LoadLibraryW(L"shell32.dll");
	shell_execute = shell ? (shell_execute_ex_fn)(void *)GetProcAddress(shell, "ShellExecuteExW") : NULL;
	if (!shell_execute) {
		fputs("Windows cannot display an administrator prompt here; run this command in an administrator console.\n", stderr);
		goto done;
	}
	memset(&request, 0, sizeof(request));
	request.cbSize = sizeof(request);
	request.fMask = SEE_MASK_NOCLOSEPROCESS;
	request.lpVerb = L"runas";
	request.lpFile = executable;
	request.lpParameters = parameters;
	request.nShow = SW_SHOWNORMAL;
	if (!shell_execute(&request)) {
		fprintf(stderr, "Administrator request failed or was cancelled: Windows error %lu.\n",
			(unsigned long)GetLastError());
		goto done;
	}
	if (!request.hProcess) {
		fputs("Administrator request returned no process handle.\n", stderr);
		goto done;
	}
	wait_result = WaitForSingleObject(request.hProcess, INFINITE);
	if (wait_result == WAIT_OBJECT_0 && GetExitCodeProcess(request.hProcess, &exit_code))
		result = (int)exit_code;
	else fputs("Could not read the elevated installer's result.\n", stderr);
	CloseHandle(request.hProcess);
done:
	if (shell) FreeLibrary(shell);
	HeapFree(GetProcessHeap(), 0, parameters);
	return result;
}

/* A service with this fixed name may belong to another installation. Never
 * change it unless its executable path is exactly the current executable. */
static int service_uses_current_executable(SC_HANDLE service, const wchar_t *executable) {
	LPQUERY_SERVICE_CONFIGW config;
	const wchar_t *start, *end;
	DWORD needed = 0;
	int same = 0;
	QueryServiceConfigW(service, NULL, 0, &needed);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !needed) return -1;
	config = malloc(needed);
	if (!config) return -1;
	if (!QueryServiceConfigW(service, config, needed, &needed)) {
		free(config);
		return -1;
	}
	start = config->lpBinaryPathName;
	if (start && *start == L'"') {
		start++;
		end = wcschr(start, L'"');
	} else {
		end = start;
		while (end && *end && *end != L' ' && *end != L'\t') end++;
	}
	if (start && end && (size_t)(end - start) == wcslen(executable) &&
			_wcsnicmp(start, executable, (size_t)(end - start)) == 0) same = 1;
	free(config);
	return same;
}

static int stop_service_for_replacement(SC_HANDLE service) {
	SERVICE_STATUS status;
	int i;
	if (!QueryServiceStatus(service, &status)) return 0;
	if (status.dwCurrentState == SERVICE_STOPPED) return 1;
	if (getenv("SSH_CONNECTION") && getenv("SSH_CONNECTION")[0]) {
		fputs("Run the replacement from a local Windows console; stopping the SSH service would end this command.\n",
			stderr);
		return 0;
	}
	if (status.dwCurrentState != SERVICE_STOP_PENDING &&
			!ControlService(service, SERVICE_CONTROL_STOP, &status) &&
			GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
		fprintf(stderr, "Could not stop the existing DropbearWin service: error %lu.\n",
			(unsigned long)GetLastError());
		return 0;
	}
	for (i = 0; i < 120; i++) {
		if (!QueryServiceStatus(service, &status)) return 0;
		if (status.dwCurrentState == SERVICE_STOPPED) return 1;
		Sleep(250);
	}
	fputs("The existing DropbearWin service did not stop within 30 seconds.\n", stderr);
	return 0;
}

static int install_executable_path(const wchar_t *source, wchar_t *directory,
		wchar_t *destination, size_t capacity) {
	wchar_t drive[8], *name = wcsrchr(source, L'\\');
	DWORD length = GetEnvironmentVariableW(L"SystemDrive", drive, 8);
	int written;
	if (!name || !length || length >= 8 || drive[1] != L':' || drive[2]) return 0;
	written = _snwprintf(directory, capacity, L"%ls\\Program Files\\DropbearWin", drive);
	if (written <= 0 || (size_t)written >= capacity) return 0;
	written = _snwprintf(destination, capacity, L"%ls%ls", directory, name);
	return written > 0 && (size_t)written < capacity;
}

/* ProgramData is writable by ordinary users by default. Keep the account
 * hash and private host key accessible only to SYSTEM and Administrators. */
static int secure_installed_data_directory(const char *path) {
	PSECURITY_DESCRIPTOR descriptor = NULL;
	SECURITY_ATTRIBUTES security;
	DWORD attributes;
	int ok;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
			L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1,
			&descriptor, NULL)) return 0;
	memset(&security, 0, sizeof(security));
	security.nLength = sizeof(security);
	security.lpSecurityDescriptor = descriptor;
	ok = CreateDirectoryA(path, &security) || GetLastError() == ERROR_ALREADY_EXISTS;
	attributes = ok ? GetFileAttributesA(path) : INVALID_FILE_ATTRIBUTES;
	ok = ok && attributes != INVALID_FILE_ATTRIBUTES &&
		(attributes & FILE_ATTRIBUTE_DIRECTORY) &&
		SetFileSecurityA(path, DACL_SECURITY_INFORMATION, descriptor);
	LocalFree(descriptor);
	return ok;
}

static int secure_installed_data_file(const char *path) {
	PSECURITY_DESCRIPTOR descriptor = NULL;
	int ok;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
			L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1,
			&descriptor, NULL)) return 0;
	ok = SetFileSecurityA(path, DACL_SECURITY_INFORMATION, descriptor);
	LocalFree(descriptor);
	return ok;
}

static int same_file_bytes(const char *left, const char *right) {
	HANDLE a = INVALID_HANDLE_VALUE, b = INVALID_HANDLE_VALUE;
	unsigned char ab[4096], bb[4096];
	DWORD ac, bc;
	int equal = 0;
	a = CreateFileA(left, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	b = CreateFileA(right, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (a == INVALID_HANDLE_VALUE || b == INVALID_HANDLE_VALUE) goto done;
	for (;;) {
		if (!ReadFile(a, ab, sizeof(ab), &ac, NULL) ||
				!ReadFile(b, bb, sizeof(bb), &bc, NULL) || ac != bc ||
				memcmp(ab, bb, ac)) goto done;
		if (!ac) { equal = 1; break; }
	}
done:
	if (a != INVALID_HANDLE_VALUE) CloseHandle(a);
	if (b != INVALID_HANDLE_VALUE) CloseHandle(b);
	return equal;
}

/* Never overwrite an existing, different account or host identity. */
static int install_data_file(const char *source_dir, const char *target_dir,
		const char *name, int required, int *created) {
	char source[MAX_PATH], target[MAX_PATH];
	DWORD attributes;
	*created = 0;
	if (snprintf(source, sizeof(source), "%s\\%s", source_dir, name) >= (int)sizeof(source) ||
			snprintf(target, sizeof(target), "%s\\%s", target_dir, name) >= (int)sizeof(target)) return 0;
	if (!_stricmp(source, target)) return GetFileAttributesA(target) != INVALID_FILE_ATTRIBUTES || !required;
	attributes = GetFileAttributesA(source);
	if (attributes == INVALID_FILE_ATTRIBUTES) return !required;
	if (attributes & FILE_ATTRIBUTE_DIRECTORY) return 0;
	attributes = GetFileAttributesA(target);
	if (attributes != INVALID_FILE_ATTRIBUTES) {
		if (attributes & FILE_ATTRIBUTE_DIRECTORY || !same_file_bytes(source, target)) {
			fprintf(stderr, "Installed %s differs from the portable copy; preserving both.\n", name);
			return 0;
		}
		return 1;
	}
	*created = 1;
	if (!CopyFileA(source, target, TRUE)) {
		DeleteFileA(target);
		return 0;
	}
	return same_file_bytes(source, target);
}

static void clean_portable_data(const wchar_t *source_exe, const char *source_dir,
		const char *target_dir) {
	char portable[MAX_PATH], source[MAX_PATH];
	wchar_t executable[32768], *slash;
	const char *names[] = { "account.conf", "hostkey_ed25519", "dropbear.pid", "service.log",
		"SKILL.md", "mcp.json", "SKILL.md.tmp", "mcp.json.tmp", "bundle-manifest.json",
		"dropbear_mcp.py", "windows_exec.py", "requirements-mcp.txt", "session_screenshot.ps1",
		"session_display.ps1", "mcp-reference.md", "agent-mcp.md", "session_client.py",
		"session_interact.ps1", "session_interact.cs" };
	size_t i;
	if (!_stricmp(source_dir, target_dir) || wcslen(source_exe) >= 32768) return;
	wcscpy(executable, source_exe);
	slash = wcsrchr(executable, L'\\');
	if (!slash) return;
	*slash = 0;
	if (WideCharToMultiByte(CP_ACP, 0, executable, -1, portable,
			sizeof(portable), NULL, NULL) == 0) return;
	if (strlen(portable) + sizeof("\\dropbear-win-data") > sizeof(portable)) return;
	strcat(portable, "\\dropbear-win-data");
	if (_stricmp(portable, source_dir)) return;
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (snprintf(source, sizeof(source), "%s\\%s", source_dir, names[i]) >= (int)sizeof(source)) return;
		if (GetFileAttributesA(source) != INVALID_FILE_ATTRIBUTES && !DeleteFileA(source)) {
			fprintf(stderr, "Installed, but could not remove portable %s.\n", source);
			return;
		}
	}
	if (!RemoveDirectoryA(source_dir))
		fprintf(stderr, "Installed; portable data directory is not empty: %s\n", source_dir);
}

/* The portable process cannot delete its own running EXE, and may still hold
 * its log open. Start the installed copy, wait for the portable parent to
 * exit, then remove only the EXE and the known adjacent data files. */
static int launch_portable_cleanup(const wchar_t *installed_exe,
		const wchar_t *source_exe, const char *portable_data) {
	wchar_t data[32768], command[4096], working_directory[32768], *slash;
	STARTUPINFOW startup;
	PROCESS_INFORMATION process;
	int written;
	if (wcschr(installed_exe, L'"') || wcschr(source_exe, L'"') ||
			!MultiByteToWideChar(CP_ACP, 0, portable_data, -1,
				data, sizeof(data) / sizeof(data[0])) || wcschr(data, L'"')) return 0;
	written = _snwprintf(command, sizeof(command) / sizeof(command[0]),
		L"\"%ls\" --cleanup-portable %lu \"%ls\" \"%ls\"",
		installed_exe, (unsigned long)GetCurrentProcessId(), source_exe, data);
	if (written <= 0 || written >= (int)(sizeof(command) / sizeof(command[0]))) return 0;
	if (wcslen(installed_exe) >= sizeof(working_directory) / sizeof(working_directory[0])) return 0;
	wcscpy(working_directory, installed_exe);
	slash = wcsrchr(working_directory, L'\\');
	if (!slash) return 0;
	*slash = 0;
	memset(&startup, 0, sizeof(startup));
	memset(&process, 0, sizeof(process));
	startup.cb = sizeof(startup);
	if (!CreateProcessW(installed_exe, command, NULL, NULL, FALSE,
			CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB,
			NULL, working_directory, &startup, &process)) {
		DWORD error = GetLastError();
		/* Task Scheduler and other launchers can forbid job breakaway. The
		 * cleanup child can still wait for this installer inside that job. */
		if (error != ERROR_ACCESS_DENIED ||
				!CreateProcessW(installed_exe, command, NULL, NULL, FALSE,
					CREATE_NO_WINDOW, NULL, working_directory, &startup, &process)) {
			fprintf(stderr, "Could not start portable cleanup: Windows error %lu.\n",
				(unsigned long)GetLastError());
			return 0;
		}
	}
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	printf("Portable cleanup will finish after this process exits: %ls\n", source_exe);
	return 1;
}

int dropbear_win_cleanup_portable_main(int argc, char **argv) {
	wchar_t current[32768], install_dir[32768], installed_exe[32768];
	wchar_t marker[32768], source_exe[32768], source_directory[32768];
	wchar_t expected_data[32768], requested_data[32768];
	wchar_t *source_dir, *source_name, *current_name;
	char installed_data[MAX_PATH], *end;
	HANDLE parent = NULL;
	DWORD length, parent_id, attributes, waited;
	int written, result = 1, retries;

	if (argc != 5 || strcmp(argv[1], "--cleanup-portable") ||
			!MultiByteToWideChar(CP_ACP, 0, argv[3], -1, source_exe,
				sizeof(source_exe) / sizeof(source_exe[0])) ||
			!MultiByteToWideChar(CP_ACP, 0, argv[4], -1, requested_data,
				sizeof(requested_data) / sizeof(requested_data[0]))) goto done;
	parent_id = strtoul(argv[2], &end, 10);
	if (!parent_id || !end || *end) goto done;
	length = GetModuleFileNameW(NULL, current, sizeof(current) / sizeof(current[0]));
	if (!length || length >= sizeof(current) / sizeof(current[0]) ||
			!install_executable_path(current, install_dir, installed_exe,
				sizeof(installed_exe) / sizeof(installed_exe[0])) ||
			_wcsicmp(current, installed_exe) ||
			!dropbear_win_installed_data_path(installed_data, sizeof(installed_data))) goto done;
	written = _snwprintf(marker, sizeof(marker) / sizeof(marker[0]),
		L"%ls\\dropbear-win.installed", install_dir);
	attributes = written > 0 && written < (int)(sizeof(marker) / sizeof(marker[0]))
		? GetFileAttributesW(marker) : INVALID_FILE_ATTRIBUTES;
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) ||
			_wcsicmp(source_exe, current) == 0 || wcslen(source_exe) >= 32768) goto done;

	wcscpy(expected_data, source_exe);
	source_dir = wcsrchr(expected_data, L'\\');
	source_name = wcsrchr(source_exe, L'\\');
	current_name = wcsrchr(current, L'\\');
	if (!source_dir || !source_name || !current_name ||
			_wcsicmp(source_name + 1, current_name + 1)) goto done;
	*source_dir = 0;
	wcscpy(source_directory, expected_data);
	written = _snwprintf(expected_data + wcslen(expected_data),
		(sizeof(expected_data) / sizeof(expected_data[0])) - wcslen(expected_data),
		L"\\dropbear-win-data");
	if (written <= 0 || _wcsicmp(expected_data, requested_data) ||
			!_stricmp(argv[4], installed_data)) goto done;

	parent = OpenProcess(SYNCHRONIZE, FALSE, parent_id);
	if (parent) {
		waited = WaitForSingleObject(parent, 60000);
		if (waited != WAIT_OBJECT_0) goto done;
	} else if (GetLastError() != ERROR_INVALID_PARAMETER) {
		goto done;
	}
	clean_portable_data(source_exe, argv[4], installed_data);
	for (retries = 0; retries < 40; retries++) {
		if (DeleteFileW(source_exe) || GetLastError() == ERROR_FILE_NOT_FOUND ||
				GetLastError() == ERROR_PATH_NOT_FOUND) {
			/* Remove the portable folder only when it is now empty. */
			RemoveDirectoryW(source_directory);
			result = 0;
			break;
		}
		Sleep(100);
	}
done:
	if (parent) CloseHandle(parent);
	return result;
}

static int install_registered_service(int argc, char **argv, DWORD start_type) {
	WCHAR source_exe[32768], install_dir[32768], installed_exe[32768];
	WCHAR backup_exe[32768], marker[32768];
	char portable_data[MAX_PATH], installed_data[MAX_PATH];
	char account_path[MAX_PATH], hostkey_path[MAX_PATH], portable_account[MAX_PATH];
	char expected_portable[MAX_PATH];
	const char *migration_data;
	wchar_t *command_line = NULL;
	SC_HANDLE manager = NULL, service = NULL;
	HANDLE marker_file;
	DWORD length, attributes, open_error;
	int match, installed_match, installed_upgrade = 0, replacing_service = 0;
	int marker_length, backup_length, result = 1, copied_exe = 0, backed_up_exe = 0;
	int created_account = 0, created_hostkey = 0, created_marker = 0;
	int created_data_dir = 0;
	struct dropbear_win_bundle_transaction *bundle = NULL;

	length = GetModuleFileNameW(NULL, source_exe, 32768);
	if (!length || length >= 32768 ||
			!install_executable_path(source_exe, install_dir, installed_exe, 32768) ||
			!dropbear_win_installed_data_path(installed_data, sizeof(installed_data)) ||
			strlen(dropbear_win_data_dir()) >= sizeof(portable_data)) {
		fputs("Could not resolve the installed EXE and data paths.\n", stderr);
		return 1;
	}
	strcpy(portable_data, dropbear_win_data_dir());
	migration_data = portable_data;
	{
		wchar_t source_dir[32768], *slash;
		if (wcslen(source_exe) >= 32768) return 1;
		wcscpy(source_dir, source_exe);
		slash = wcsrchr(source_dir, L'\\');
		if (!slash) return 1;
		*slash = 0;
		if (!WideCharToMultiByte(CP_ACP, 0, source_dir, -1,
				expected_portable, sizeof(expected_portable), NULL, NULL) ||
				strlen(expected_portable) + sizeof("\\dropbear-win-data") >
					sizeof(expected_portable)) return 1;
		strcat(expected_portable, "\\dropbear-win-data");
	}
	if (_stricmp(portable_data, expected_portable) &&
			_stricmp(portable_data, installed_data)) {
		fputs("Installer data must come from this EXE or the installed data directory.\n", stderr);
		return 1;
	}
	marker_length = _snwprintf(marker, 32768, L"%ls\\dropbear-win.installed", install_dir);
	backup_length = _snwprintf(backup_exe, 32768, L"%ls.install-backup-%lu", installed_exe,
		(unsigned long)GetCurrentProcessId());
	if (marker_length <= 0 || marker_length >= 32768 ||
			backup_length <= 0 || backup_length >= 32768 ||
			snprintf(account_path, sizeof(account_path), "%s\\account.conf", installed_data)
				>= (int)sizeof(account_path) ||
			snprintf(hostkey_path, sizeof(hostkey_path), "%s\\hostkey_ed25519", installed_data)
				>= (int)sizeof(hostkey_path) ||
			snprintf(portable_account, sizeof(portable_account), "%s\\account.conf", portable_data)
				>= (int)sizeof(portable_account)) return 1;
	if (!dropbear_win_account_file_path() ||
			_stricmp(dropbear_win_account_file_path(), portable_account)) {
		fputs("A custom account file cannot be migrated automatically.\n", stderr);
		return 1;
	}
	manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
	if (!manager) {
		fprintf(stderr, "Could not open the service manager: error %lu.\n",
			(unsigned long)GetLastError());
		goto done;
	}
	service = OpenServiceW(manager, WIN_SETUP_NAME,
		SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG |
		SERVICE_STOP | SERVICE_START);
	if (service) {
		match = service_uses_current_executable(service, source_exe);
		installed_match = service_uses_current_executable(service, installed_exe);
		if (match != 1 && installed_match != 1) {
			replacing_service = 1;
		}
		if (match != 1 && installed_match == 1) {
			attributes = GetFileAttributesW(marker);
			if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
				installed_upgrade = 1;
				migration_data = installed_data;
			} else {
				replacing_service = 1;
			}
		}
		if (!stop_service_for_replacement(service)) goto done;
	} else {
		open_error = GetLastError();
		if (open_error != ERROR_SERVICE_DOES_NOT_EXIST) {
			fprintf(stderr, "Could not inspect DropbearWin: error %lu.\n",
				(unsigned long)open_error);
			goto done;
		}
	}
	attributes = GetFileAttributesW(install_dir);
	if (attributes == INVALID_FILE_ATTRIBUTES && !CreateDirectoryW(install_dir, NULL)) {
		fputs("Could not create the installed EXE directory.\n", stderr);
		goto done;
	}
	attributes = GetFileAttributesW(install_dir);
	if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) goto done;
	created_data_dir = GetFileAttributesA(installed_data) == INVALID_FILE_ATTRIBUTES;
	if (!secure_installed_data_directory(installed_data)) {
		fputs("Could not secure the installed data directory.\n", stderr);
		goto done;
	}
	if (!install_data_file(migration_data, installed_data, "account.conf", 1, &created_account) ||
			!install_data_file(migration_data, installed_data, "hostkey_ed25519", 0, &created_hostkey)) {
		fputs("Could not migrate the portable account and host identity.\n", stderr);
		goto done;
	}
	if (!secure_installed_data_file(account_path) ||
			(GetFileAttributesA(hostkey_path) != INVALID_FILE_ATTRIBUTES &&
				!secure_installed_data_file(hostkey_path))) {
		fputs("Could not secure the installed account or host key.\n", stderr);
		goto done;
	}
	if (_wcsicmp(source_exe, installed_exe)) {
		if (GetFileAttributesW(installed_exe) != INVALID_FILE_ATTRIBUTES) {
			if (!CopyFileW(installed_exe, backup_exe, TRUE)) {
				fputs("Could not back up the installed EXE.\n", stderr);
				goto done;
			}
			backed_up_exe = 1;
		}
		copied_exe = 1;
		if (!CopyFileW(source_exe, installed_exe, FALSE)) {
			fputs("Could not copy the EXE to Program Files.\n", stderr);
			goto done;
		}
	}
	if (GetFileAttributesW(marker) == INVALID_FILE_ATTRIBUTES) {
		marker_file = CreateFileW(marker, GENERIC_WRITE, 0, NULL, CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if (marker_file == INVALID_HANDLE_VALUE) goto done;
		CloseHandle(marker_file);
		created_marker = 1;
	}
	if (!dropbear_win_bundle_begin(install_dir, &bundle)) goto done;
	command_line = dropbear_win_build_service_command_line(installed_exe, argc, argv);
	if (!command_line) goto done;
	if (service) {
		if (!ChangeServiceConfigW(service, SERVICE_WIN32_OWN_PROCESS, start_type,
				SERVICE_ERROR_NORMAL, command_line, NULL, NULL, L"", L"LocalSystem", NULL,
				WIN_SETUP_DISPLAY)) {
			fprintf(stderr, "Could not update DropbearWin: error %lu.\n",
				(unsigned long)GetLastError());
			goto done;
		}
	} else {
		service = CreateServiceW(manager, WIN_SETUP_NAME, WIN_SETUP_DISPLAY,
			SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, start_type,
			SERVICE_ERROR_NORMAL, command_line, NULL, NULL, NULL, NULL, NULL);
		if (!service) {
			fprintf(stderr, "Could not install DropbearWin: error %lu.\n",
				(unsigned long)GetLastError());
			goto done;
		}
	}
	printf("Service %s: %ls\nEXE: %ls\nData: %s\n",
		installed_upgrade ? "upgraded" : (replacing_service ? "replaced" : "installed"), WIN_SETUP_NAME,
		installed_exe, installed_data);
	write_uninstall_script(installed_exe);
	if (StartServiceW(service, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
		printf("Service started: %ls\n", WIN_SETUP_NAME);
	} else {
		fprintf(stderr,
			"Service installed, but it could not start (Windows error %lu); AUTO_START remains enabled.\n",
			(unsigned long)GetLastError());
	}
	result = 0;
done:
	if (service) CloseServiceHandle(service);
	if (manager) CloseServiceHandle(manager);
	if (!dropbear_win_bundle_finish(bundle, !result))
		fputs("Some agent resource backup files require manual cleanup.\n", stderr);
	if (result) {
		if (created_marker) DeleteFileW(marker);
		if (backed_up_exe && !CopyFileW(backup_exe, installed_exe, FALSE))
			fputs("Could not restore the previous installed EXE.\n", stderr);
		else if (copied_exe && !backed_up_exe) DeleteFileW(installed_exe);
		if (created_hostkey) DeleteFileA(hostkey_path);
		if (created_account) DeleteFileA(account_path);
		if (created_data_dir) RemoveDirectoryA(installed_data);
	} else {
		/* Old builds published these generated snapshots in ProgramData. */
		const char *old_names[] = { "SKILL.md", "mcp.json", "SKILL.md.tmp", "mcp.json.tmp" };
		size_t i;
		for (i = 0; i < sizeof(old_names) / sizeof(old_names[0]); i++) {
			char old_path[MAX_PATH];
			if (snprintf(old_path, sizeof(old_path), "%s\\%s", installed_data, old_names[i]) < (int)sizeof(old_path))
				DeleteFileA(old_path);
		}
		if (_wcsicmp(source_exe, installed_exe) &&
				!launch_portable_cleanup(installed_exe, source_exe, expected_portable)) {
			clean_portable_data(source_exe, expected_portable, installed_data);
			if (!DeleteFileW(source_exe)) {
				if (MoveFileExW(source_exe, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
					printf("Portable EXE scheduled for removal at next restart: %ls\n", source_exe);
				else fputs("Installed, but the portable EXE must be removed manually.\n", stderr);
			}
		}
	}
	if (backed_up_exe) DeleteFileW(backup_exe);
	if (command_line) HeapFree(GetProcessHeap(), 0, command_line);
	return result;
}

static int remove_installed_file(const wchar_t *path, int *restart_required) {
	DWORD attributes = GetFileAttributesW(path);
	if (attributes == INVALID_FILE_ATTRIBUTES)
		return GetLastError() == ERROR_FILE_NOT_FOUND ||
			GetLastError() == ERROR_PATH_NOT_FOUND;
	if (attributes & FILE_ATTRIBUTE_DIRECTORY) return 0;
	if (DeleteFileW(path)) return 1;
	if (!MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) return 0;
	*restart_required = 1;
	return 1;
}

static int remove_installed_data(const char *directory) {
	const char *names[] = { "account.conf", "hostkey_ed25519", "dropbear.pid", "service.log",
		"SKILL.md", "mcp.json", "SKILL.md.tmp", "mcp.json.tmp", "bundle-manifest.json",
		"dropbear_mcp.py", "windows_exec.py", "requirements-mcp.txt", "session_screenshot.ps1",
		"session_display.ps1", "mcp-reference.md", "agent-mcp.md", "session_client.py",
		"session_interact.ps1", "session_interact.cs" };
	char path[MAX_PATH];
	size_t i;
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		DWORD attributes;
		if (snprintf(path, sizeof(path), "%s\\%s", directory, names[i]) >= (int)sizeof(path)) return 0;
		attributes = GetFileAttributesA(path);
		if (attributes == INVALID_FILE_ATTRIBUTES) {
			if (GetLastError() != ERROR_FILE_NOT_FOUND &&
					GetLastError() != ERROR_PATH_NOT_FOUND) return 0;
			continue;
		}
		if (attributes & FILE_ATTRIBUTE_DIRECTORY || !DeleteFileA(path)) return 0;
	}
	/* Unknown files are left alone rather than recursively deleted. */
	if (RemoveDirectoryA(directory) || GetLastError() == ERROR_PATH_NOT_FOUND ||
			GetLastError() == ERROR_FILE_NOT_FOUND) return 1;
	fprintf(stderr, "Installed data directory still contains other files: %s\n", directory);
	return 0;
}

int dropbear_win_uninstall(int argc, char **argv) {
	wchar_t current[32768], install_dir[32768], installed_exe[32768];
	wchar_t marker[32768], script[32768], other_exe[32768];
	char installed_data[MAX_PATH];
	SC_HANDLE manager = NULL, service = NULL;
	SERVICE_STATUS status;
	DWORD length, error, marker_attributes;
	int purge_data = 0, purge_failed = 0, restart_required = 0, result = 1;
	int i, removed_current = 0;
	int marker_length, script_length, other_length;
	if (argc == 3 && !strcmp(argv[2], "--purge-data")) purge_data = 1;
	else if (argc != 2) {
		fputs("Usage: dropbear-win.exe --uninstall [--purge-data]\n", stderr);
		return 2;
	}
	if (!current_process_is_administrator()) {
		fputs("Run the installed EXE as Administrator to uninstall.\n", stderr);
		return 1;
	}
	if (getenv("SSH_CONNECTION") && getenv("SSH_CONNECTION")[0]) {
		fputs("Run uninstall from a local Windows console; stopping SSH would end this command.\n", stderr);
		return 1;
	}
	length = GetModuleFileNameW(NULL, current, 32768);
	if (!length || length >= 32768 ||
			!install_executable_path(current, install_dir, installed_exe, 32768) ||
			!dropbear_win_installed_data_path(installed_data, sizeof(installed_data)) ||
			_wcsicmp(current, installed_exe)) {
		fputs("Run --uninstall from the EXE in the installed Program Files directory.\n", stderr);
		return 1;
	}
	marker_length = _snwprintf(marker, 32768, L"%ls\\dropbear-win.installed", install_dir);
	script_length = _snwprintf(script, 32768, L"%ls\\%ls", install_dir, WIN_SETUP_SCRIPT);
	marker_attributes = marker_length > 0 && marker_length < 32768
		? GetFileAttributesW(marker) : INVALID_FILE_ATTRIBUTES;
	if (marker_length <= 0 || marker_length >= 32768 ||
			script_length <= 0 || script_length >= 32768 ||
			marker_attributes == INVALID_FILE_ATTRIBUTES ||
			(marker_attributes & FILE_ATTRIBUTE_DIRECTORY)) {
		fputs("This EXE has no DropbearWin installation marker.\n", stderr);
		return 1;
	}
	manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!manager) goto done;
	service = OpenServiceW(manager, WIN_SETUP_NAME,
		SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);
	if (service) {
		if (service_uses_current_executable(service, installed_exe) != 1) {
			fputs("DropbearWin points to another EXE; leaving it unchanged.\n", stderr);
			goto done;
		}
		for (i = 0; i < 120; i++) {
			if (!QueryServiceStatus(service, &status)) goto done;
			if (status.dwCurrentState == SERVICE_STOPPED) break;
			if (status.dwCurrentState == SERVICE_RUNNING &&
					!ControlService(service, SERVICE_CONTROL_STOP, &status) &&
					GetLastError() != ERROR_SERVICE_NOT_ACTIVE) goto done;
			Sleep(250);
		}
		if (i == 120) {
			fputs("DropbearWin did not stop within 30 seconds.\n", stderr);
			goto done;
		}
		if (!DeleteService(service) && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) {
			fprintf(stderr, "Could not delete DropbearWin: Windows error %lu.\n",
				(unsigned long)GetLastError());
			goto done;
		}
	} else {
		error = GetLastError();
		if (error != ERROR_SERVICE_DOES_NOT_EXIST) goto done;
	}
	if (service) CloseServiceHandle(service);
	service = NULL;
	CloseServiceHandle(manager); manager = NULL;
	if (purge_data && !remove_installed_data(installed_data)) {
		fputs("Installed data could not be fully deleted; continuing program removal.\n", stderr);
		purge_failed = 1;
	}
	/* Only the compiled-in names are owned by the installer; preserve other files. */
	for (i = 0; dropbear_win_bundle_name((unsigned int)i); i++) {
		other_length = _snwprintf(other_exe, 32768, L"%ls\\%ls", install_dir,
			dropbear_win_bundle_name((unsigned int)i));
		if (other_length <= 0 || other_length >= 32768 ||
				!remove_installed_file(other_exe, &restart_required)) goto done;
	}
	if (!remove_installed_file(script, &restart_required)) goto done;
	/* A second architecture may have been copied into the same install folder. */
	other_length = _snwprintf(other_exe, 32768, L"%ls\\dropbear-win-x64.exe", install_dir);
	if (other_length <= 0 || other_length >= 32768) goto done;
	removed_current = !_wcsicmp(other_exe, installed_exe);
	if (!remove_installed_file(other_exe, &restart_required)) goto done;
	other_length = _snwprintf(other_exe, 32768, L"%ls\\dropbear-win-x86.exe", install_dir);
	if (other_length <= 0 || other_length >= 32768) goto done;
	if (!_wcsicmp(other_exe, installed_exe)) removed_current = 1;
	if (!remove_installed_file(other_exe, &restart_required) ||
			(!removed_current && !remove_installed_file(installed_exe, &restart_required))) goto done;
	if (!remove_installed_file(marker, &restart_required)) goto done;
	if (!RemoveDirectoryW(install_dir)) {
		if (MoveFileExW(install_dir, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
			restart_required = 1;
		else {
			fputs("Service removed, but the install directory still needs manual cleanup.\n", stderr);
			goto done;
		}
	}
	printf("DropbearWin uninstalled. Data %s: %s\n",
		purge_data ? (purge_failed ? "partly removed" : "removed") : "preserved",
		installed_data);
	if (restart_required) fputs("Restart Windows to finish removing in-use files.\n", stdout);
	result = purge_failed ? 1 : 0;
done:
	if (service) CloseServiceHandle(service);
	if (manager) CloseServiceHandle(manager);
	return result;
}

int dropbear_win_install_autostart(int argc, char **argv) {
	char executable[MAX_PATH], portable_account[MAX_PATH];
	char installed_data[MAX_PATH], retained_account[MAX_PATH];
	char assignment[MAX_PATH + 32], *slash;
	if (!current_process_is_administrator()) {
		if (!strcmp(argv[1], "--install-autostart-elevated")) {
			fputs("Administrator rights are required to install the automatic Windows service.\n", stderr);
			return 1;
		}
		return request_autostart_elevation(argc, argv);
	}
	/* An installer invoked through SSH inherits the service's data overrides.
	 * Installation must read the portable data beside this EXE instead. */
	if (_putenv("DROPBEAR_WIN_DATA_DIR=") ||
			_putenv("DROPBEAR_WIN_ACCOUNT_FILE=") ||
			!SetEnvironmentVariableA("DROPBEAR_WIN_DATA_DIR", NULL) ||
			!SetEnvironmentVariableA("DROPBEAR_WIN_ACCOUNT_FILE", NULL)) {
		fputs("Could not select this EXE's portable data directory.\n", stderr);
		return 1;
	}
	/* A default uninstall retains ProgramData. A later install from a fresh
	 * portable EXE reuses that account and host identity instead of asking for
	 * a new password that would conflict with the retained files. */
	if (!GetModuleFileNameA(NULL, executable, sizeof(executable))) return 1;
	slash = strrchr(executable, '\\');
	if (!slash || !dropbear_win_installed_data_path(installed_data, sizeof(installed_data))) return 1;
	*slash = 0;
	if (snprintf(portable_account, sizeof(portable_account), "%s\\dropbear-win-data\\account.conf",
			executable) >= (int)sizeof(portable_account) ||
			snprintf(retained_account, sizeof(retained_account), "%s\\account.conf",
				installed_data) >= (int)sizeof(retained_account)) return 1;
	if (GetFileAttributesA(portable_account) == INVALID_FILE_ATTRIBUTES &&
			GetFileAttributesA(retained_account) != INVALID_FILE_ATTRIBUTES) {
		if (snprintf(assignment, sizeof(assignment), "DROPBEAR_WIN_DATA_DIR=%s",
				installed_data) >= (int)sizeof(assignment) ||
				_putenv(assignment) ||
				!SetEnvironmentVariableA("DROPBEAR_WIN_DATA_DIR", installed_data)) return 1;
	}
	if (!dropbear_win_prepare()) {
		fputs("Autostart setup stopped before the SSH account was ready.\n", stderr);
		return 1;
	}
	/* argv + 1 starts with the installer switch, which the command builder skips. */
	return install_registered_service(argc - 1, argv + 1, SERVICE_AUTO_START);
}

void dropbear_win_maybe_register_service(int argc, char **argv) {
	SC_HANDLE service;
	wchar_t executable[32768], install_dir[32768], installed_exe[32768], marker[32768];
	DWORD attributes;
	int current_match, installed_match, marker_length, valid_install;
	int upgrading = 0, replacing_service = 0, migrating_service = 0;
	if (service_mode || !_isatty(_fileno(stdin))) return;
	if (!GetModuleFileNameW(NULL, executable, 32768)) return;

	if (open_existing_service(SERVICE_QUERY_CONFIG, &service)) {
		current_match = service_uses_current_executable(service, executable);
		installed_match = install_executable_path(executable, install_dir, installed_exe, 32768)
			? service_uses_current_executable(service, installed_exe) : 0;
		marker_length = installed_match == 1
			? _snwprintf(marker, 32768, L"%ls\\dropbear-win.installed", install_dir) : 0;
		attributes = marker_length > 0 && marker_length < 32768
			? GetFileAttributesW(marker) : INVALID_FILE_ATTRIBUTES;
		valid_install = installed_match == 1 && attributes != INVALID_FILE_ATTRIBUTES &&
			!(attributes & FILE_ATTRIBUTE_DIRECTORY);
		CloseServiceHandle(service);
		/* A service registration may still point at a desktop/portable EXE.
		 * Only the managed path plus its marker proves installation completed. */
		if (current_match == 1 && valid_install && !_wcsicmp(executable, installed_exe)) {
			write_uninstall_script(executable);
			return;
		}
		if (current_match == 1) {
			migrating_service = 1;
		} else if (!valid_install) {
			replacing_service = 1;
		} else {
			upgrading = 1;
		}
	}

	if (migrating_service) {
		fputs("\nA service named \"DropbearWin\" points to this EXE, but this copy is not a managed installation.\n"
			"Installing will migrate the EXE to the system drive's Program Files\\DropbearWin directory,\n"
			"move its data to the installed ProgramData directory, and update the service for automatic startup.\n"
			"Continue with the installation? [y/N] ", stdout);
	} else if (upgrading) {
		fputs("\nAn existing DropbearWin installation was found.\n"
			"Installing this version will remove the old installed program and replace its service configuration.\n"
			"The installed SSH account and host key will be preserved.\n"
			"Continue with the upgrade? [y/N] ", stdout);
	} else if (replacing_service) {
		fputs("\nA service named \"DropbearWin\" already exists and points to another program.\n"
			"Installing this version will stop that service and replace its service configuration.\n"
			"Continue with the replacement? [y/N] ", stdout);
	} else {
		fputs("\nRegister this server as the Windows service \"DropbearWin\"? [y/N] ",
			stdout);
	}
	fflush(stdout);
	if (!read_yes_answer()) return;

	if (install_registered_service(argc, argv, SERVICE_AUTO_START)) {
		fputs(upgrading
			? "Service upgrade failed; the previous installation and portable copy were preserved.\n"
			: (replacing_service
				? "Service replacement failed; the existing service and portable copy were preserved.\n"
				: "Service registration failed; portable EXE and data were preserved.\n"), stderr);
		exit(1);
	}
	/* This process still has portable paths cached. The installed service starts
	 * as a fresh process and reads its migrated ProgramData files. */
	exit(0);
}
#endif
