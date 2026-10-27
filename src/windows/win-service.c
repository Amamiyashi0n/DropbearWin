/* Dropbear-win host lifecycle. Uses APIs available on Windows XP. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include "win-account.h"
#include <shellapi.h>

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

/* Zero-parameter deployment: the interactive console asks whether to register
 * the running binary as the Windows service, and writes an uninstall script
 * next to the executable. Registered services keep working without the
 * question; --service continues to work for scripted setups. */
#define WIN_SETUP_NAME L"DropbearWin"
#define WIN_SETUP_DISPLAY L"Dropbear for Windows"
#define WIN_SETUP_SCRIPT L"uninstall-dropbear-service.cmd"

static void write_uninstall_script(void) {
	wchar_t executable[32768], *slash;
	wchar_t path[MAX_PATH];
	char script[] =
		"@echo off\r\n"
		"rem Generated by dropbear-win. This removes the DropbearWin service.\r\n"
		"net stop DropbearWin\r\n"
		"sc delete DropbearWin\r\n"
		"pause\r\n";
	FILE *file;
	int written;
	if (!GetModuleFileNameW(NULL, executable, 32768)) return;
	slash = wcsrchr(executable, L'\\');
	if (!slash) return;
	*slash = 0;
	written = _snwprintf(path, MAX_PATH, L"%ls\\%ls", executable, WIN_SETUP_SCRIPT);
	if (written <= 0 || written >= MAX_PATH) return;
	file = _wfopen(path, L"wb");
	if (!file) {
		fprintf(stderr, "Could not write the uninstall script (Windows error %lu).\n",
			(unsigned long)GetLastError());
		return;
	}
	fwrite(script, 1, sizeof(script) - 1, file);
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

static int open_existing_service(DWORD access, SC_HANDLE *manager_out,
		SC_HANDLE *service_out) {
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

int dropbear_win_install_autostart(int argc, char **argv) {
	WCHAR executable[32768];
	wchar_t *command_line = NULL;
	SC_HANDLE manager = NULL, service = NULL;
	DWORD length, error;
	int match, result = 1;
	if (!current_process_is_administrator()) {
		if (!strcmp(argv[1], "--install-autostart-elevated")) {
			fputs("Administrator rights are required to install the automatic Windows service.\n", stderr);
			return 1;
		}
		return request_autostart_elevation(argc, argv);
	}
	/* The explicit installer can perform first-run SSH account setup, then
	 * register the service only after configuration is valid. */
	if (!dropbear_win_prepare()) {
		fputs("Autostart setup stopped before the SSH account was ready.\n", stderr);
		return 1;
	}
	length = GetModuleFileNameW(NULL, executable, 32768);
	if (!length || length >= 32768) {
		fputs("Could not read the executable path.\n", stderr);
		return 1;
	}
	/* The first argument in argv + 1 is the installer switch. The service
	 * command builder skips it and forwards only subsequent server options. */
	command_line = dropbear_win_build_service_command_line(executable, argc - 1, argv + 1);
	if (!command_line) {
		fputs("Could not build the Windows service command line.\n", stderr);
		return 1;
	}
	manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
	if (!manager) {
		fprintf(stderr, "Could not open the Windows service manager: error %lu.\n",
			(unsigned long)GetLastError());
		goto done;
	}
	service = OpenServiceW(manager, WIN_SETUP_NAME, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
	if (service) {
		match = service_uses_current_executable(service, executable);
		if (match < 0) {
			fputs("Could not inspect the existing DropbearWin service.\n", stderr);
			goto done;
		}
		if (!match) {
			fputs("A different DropbearWin service already exists; leaving it unchanged.\n", stderr);
			goto done;
		}
		if (!ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
				SERVICE_NO_CHANGE, command_line, NULL, NULL, NULL, NULL, NULL, NULL)) {
			fprintf(stderr, "Could not enable automatic service startup: error %lu.\n",
				(unsigned long)GetLastError());
			goto done;
		}
	} else {
		error = GetLastError();
		if (error != ERROR_SERVICE_DOES_NOT_EXIST) {
			fprintf(stderr, "Could not open the DropbearWin service: error %lu.\n",
				(unsigned long)error);
			goto done;
		}
		service = CreateServiceW(manager, WIN_SETUP_NAME, WIN_SETUP_DISPLAY,
			SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
			SERVICE_ERROR_NORMAL, command_line, NULL, NULL, NULL, NULL, NULL);
		if (!service) {
			fprintf(stderr, "Could not install the automatic Windows service: error %lu.\n",
				(unsigned long)GetLastError());
			goto done;
		}
	}
	printf("Autostart enabled: %ls (Automatic). Start now with: sc start %ls\n",
		WIN_SETUP_NAME, WIN_SETUP_NAME);
	write_uninstall_script();
	result = 0;
done:
	if (service) CloseServiceHandle(service);
	if (manager) CloseServiceHandle(manager);
	HeapFree(GetProcessHeap(), 0, command_line);
	return result;
}

void dropbear_win_maybe_register_service(int argc, char **argv) {
	SC_HANDLE manager, service;
	wchar_t executable[32768], *command_line;
	if (service_mode || !_isatty(_fileno(stdin))) return;
	if (!GetModuleFileNameW(NULL, executable, 32768)) return;

	if (open_existing_service(SERVICE_QUERY_CONFIG, &manager, &service)) {
		LPQUERY_SERVICE_CONFIGW config = NULL;
		DWORD needed = 0, same_binary = 0;
		QueryServiceConfigW(service, NULL, 0, &needed);
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed) {
			config = malloc(needed);
			if (config && QueryServiceConfigW(service, config, needed, &needed)
					&& config->lpBinaryPathName) {
				wchar_t *quoted = wcschr(config->lpBinaryPathName, L'"');
				wchar_t *end;
				if (quoted) {
					quoted++;
					end = wcschr(quoted, L'"');
					if (end) {
						size_t length = (size_t)(end - quoted);
						size_t ours = wcslen(executable);
						same_binary = length == ours
							&& _wcsnicmp(quoted, executable, length) == 0;
					}
				}
			}
			free(config);
		}
		CloseServiceHandle(service);
		if (same_binary) write_uninstall_script();
		else fprintf(stderr,
			"A different service named \"%ls\" already exists; leaving it untouched.\n",
			WIN_SETUP_NAME);
		return;
	}

	fputs("\nRegister this server as the Windows service \"DropbearWin\"? [y/N] ",
		stdout);
	fflush(stdout);
	if (!read_yes_answer()) return;

	command_line = dropbear_win_build_service_command_line(executable, argc, argv);
	if (!command_line) {
		fputs("Service registration failed: out of memory.\n", stderr);
		return;
	}
	manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!manager) {
		DWORD error = GetLastError();
		fprintf(stderr, "Service registration failed: Windows error %lu.\n",
			(unsigned long)error);
		if (error == ERROR_ACCESS_DENIED)
			fputs("Administrator rights are required; run this console as administrator and retry.\n",
				stdout);
		HeapFree(GetProcessHeap(), 0, command_line);
		return;
	}
	service = CreateServiceW(manager, WIN_SETUP_NAME, WIN_SETUP_DISPLAY,
		SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL, command_line, NULL, NULL, NULL, NULL, NULL);
	CloseServiceHandle(manager);
	if (!service) {
		DWORD error = GetLastError();
		fprintf(stderr, "Service registration failed: Windows error %lu.\n",
			(unsigned long)error);
		if (error == ERROR_ACCESS_DENIED)
			fputs("Administrator rights are required; run this console as administrator and retry.\n",
				stdout);
	} else {
		CloseServiceHandle(service);
		printf("Service registered: %ls (start with: net start %ls)\n",
			WIN_SETUP_NAME, WIN_SETUP_NAME);
		write_uninstall_script();
	}
	HeapFree(GetProcessHeap(), 0, command_line);
}
#endif
