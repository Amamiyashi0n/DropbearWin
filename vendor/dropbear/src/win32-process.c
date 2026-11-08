#include "includes.h"
#include "win-account.h"
#include "session.h"
#include <wtsapi32.h>

struct process_entry {
	DWORD pid;
	HANDLE process;
	HANDLE job;
	HANDLE exit_wait;
	int notify_fd;
};

/* A dedicated helper handles one request. DBX1 fields are UTF-8, DBX2 fields
 * are canonical Base64 of UTF-8, each prefixed by its wire byte length.
 * The budget includes every header byte; application stdin remains raw. */
static unsigned int exec_budget;
static int exec_base64;
static int exec_read(void *buffer, DWORD size) {
	unsigned char *p = buffer;
	while (size) {
		DWORD count;
		if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), p, size, &count, NULL) || !count) return 0;
		p += count; size -= count;
	}
	return 1;
}

static int exec_number(unsigned int *value) {
	unsigned char bytes[4];
	if (exec_budget < 4 || !exec_read(bytes, 4)) return 0;
	exec_budget -= 4;
	*value = ((unsigned int)bytes[0] << 24) | ((unsigned int)bytes[1] << 16) |
		((unsigned int)bytes[2] << 8) | bytes[3];
	return 1;
}

static int exec_sextet(unsigned char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

/* Decode in place, rejecting whitespace, misplaced padding and nonzero pad
 * bits, rather than silently accepting multiple representations of a field. */
static int exec_decode(char *bytes, unsigned int *size) {
	unsigned int i, used = 0;
	if (*size % 4) return 0;
	for (i = 0; i < *size; i += 4) {
		int a = exec_sextet(bytes[i]), b = exec_sextet(bytes[i+1]);
		int c = exec_sextet(bytes[i+2]), d = exec_sextet(bytes[i+3]);
		int pad2 = bytes[i+2] == '=', pad1 = bytes[i+3] == '=';
		if (a < 0 || b < 0 || (!pad2 && c < 0) || (!pad1 && d < 0) ||
			(pad2 && !pad1) || ((pad1 || pad2) && i + 4 != *size) ||
			(pad2 && (b & 15)) || (pad1 && !pad2 && (c & 3))) return 0;
		bytes[used++] = (char)((a << 2) | (b >> 4));
		if (!pad2) bytes[used++] = (char)((b << 4) | (c >> 2));
		if (!pad1) bytes[used++] = (char)((c << 6) | d);
	}
	*size = used;
	return 1;
}

static wchar_t *exec_field(void) {
	unsigned int size;
	char *bytes;
	wchar_t *wide;
	int count;
	if (!exec_number(&size) || size > exec_budget) return NULL;
	exec_budget -= size;
	bytes = malloc((size_t)size + 1);
	if (!bytes) return NULL;
	if (!exec_read(bytes, size) || (exec_base64 && !exec_decode(bytes, &size)) ||
		memchr(bytes, 0, size)) {
		free(bytes); return NULL;
	}
	bytes[size] = 0;
	count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes, size + 1, NULL, 0);
	wide = count ? malloc((size_t)count * sizeof(*wide)) : NULL;
	if (wide && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes, size + 1, wide, count)) {
		free(wide); wide = NULL;
	}
	free(bytes);
	return wide;
}

/* Microsoft CRT argument quoting, including empty arguments and trailing \\. */
static int exec_argument(wchar_t *line, size_t *used, const wchar_t *arg) {
	size_t slashes = 0;
#define EXEC_CHAR(c) do { if (*used >= 32766) return 0; line[(*used)++] = (c); } while (0)
	if (*used) EXEC_CHAR(L' ');
	EXEC_CHAR(L'"');
	for (;;) {
		if (*arg == L'\\') { slashes++; arg++; continue; }
		if (*arg == L'"' || !*arg) slashes *= 2;
		while (slashes) { EXEC_CHAR(L'\\'); slashes--; }
		if (!*arg) break;
		if (*arg == L'"') EXEC_CHAR(L'\\');
		EXEC_CHAR(*arg++);
	}
	EXEC_CHAR(L'"');
	line[*used] = 0;
#undef EXEC_CHAR
	return 1;
}

static HMODULE desktop_system_library(const wchar_t *name) {
	wchar_t path[MAX_PATH];
	DWORD length = GetSystemDirectoryW(path, MAX_PATH);
	if (!length || length >= MAX_PATH || length + 1 + wcslen(name) >= MAX_PATH) return NULL;
	path[length++] = L'\\';
	wcscpy(path + length, name);
	return LoadLibraryW(path);
}

/* Launch only an explicitly requested program in the logged-on user's
 * desktop. The ordinary SSH shell keeps the service token and session 0.
 * Resolve these APIs at runtime so XP/2003 can still load the server. */
int dropbear_win_desktop_launch_main(void) {
	typedef DWORD (WINAPI *active_session_fn)(void);
	typedef BOOL (WINAPI *query_user_token_fn)(ULONG, PHANDLE);
	typedef BOOL (WINAPI *query_session_fn)(HANDLE, DWORD, WTS_INFO_CLASS, LPWSTR *, DWORD *);
	typedef void (WINAPI *wts_free_fn)(PVOID);
	typedef BOOL (WINAPI *create_environment_fn)(LPVOID *, HANDLE, BOOL);
	typedef BOOL (WINAPI *destroy_environment_fn)(LPVOID);
	typedef LPWSTR *(WINAPI *parse_command_fn)(LPCWSTR, int *);
	HMODULE kernel, wts = NULL, userenv = NULL, shell32 = NULL;
	active_session_fn active_session;
	query_user_token_fn query_user_token;
	query_session_fn query_session;
	wts_free_fn wts_free;
	create_environment_fn create_environment;
	destroy_environment_fn destroy_environment = NULL;
	parse_command_fn parse_command;
	LPWSTR *arguments = NULL;
	wchar_t *line = NULL;
	wchar_t executable[32768], directory[32768], *slash;
	wchar_t *expected_user = NULL, *end, name[256], domain[256], identity[520];
	char identity_utf8[1560];
	TOKEN_USER *token_user = NULL;
	WTS_CONNECTSTATE_CLASS *session_state = NULL;
	DWORD token_size = 0, actual_session, returned, name_size = 256, domain_size = 256;
	SID_NAME_USE sid_use;
	HANDLE token = NULL, process_token = NULL;
	LPVOID environment = NULL;
	STARTUPINFOW startup;
	PROCESS_INFORMATION process;
	TOKEN_PRIVILEGES privileges;
	LUID luid;
	DWORD session = 0xffffffffUL, attributes, error, length;
	int argc = 0, i, program_index = 2, explicit_session = 0, result = 1;
	size_t used = 0;
	const wchar_t *privilege_names[] = {
		L"SeTcbPrivilege", L"SeAssignPrimaryTokenPrivilege",
		L"SeIncreaseQuotaPrivilege"
	};

	kernel = GetModuleHandleW(L"kernel32.dll");
	shell32 = desktop_system_library(L"shell32.dll");
	wts = desktop_system_library(L"wtsapi32.dll");
	userenv = desktop_system_library(L"userenv.dll");
	parse_command = shell32 ? (parse_command_fn)(void *)GetProcAddress(shell32, "CommandLineToArgvW") : NULL;
	active_session = kernel ? (active_session_fn)(void *)GetProcAddress(kernel,
		"WTSGetActiveConsoleSessionId") : NULL;
	query_user_token = wts ? (query_user_token_fn)(void *)GetProcAddress(wts, "WTSQueryUserToken") : NULL;
	query_session = wts ? (query_session_fn)(void *)GetProcAddress(wts, "WTSQuerySessionInformationW") : NULL;
	wts_free = wts ? (wts_free_fn)(void *)GetProcAddress(wts, "WTSFreeMemory") : NULL;
	create_environment = userenv ? (create_environment_fn)(void *)GetProcAddress(userenv, "CreateEnvironmentBlock") : NULL;
	destroy_environment = userenv ? (destroy_environment_fn)(void *)GetProcAddress(userenv, "DestroyEnvironmentBlock") : NULL;
	if (!parse_command || !active_session || !query_user_token || !query_session || !wts_free ||
			!create_environment || !destroy_environment) {
		fputs("Desktop launch requires Windows Vista/Server 2008 or newer.\n", stderr);
		goto done;
	}
	arguments = parse_command(GetCommandLineW(), &argc);
	if (!arguments) goto done;
	while (program_index < argc && arguments[program_index][0] == L'-') {
		if (!wcscmp(arguments[program_index], L"--session") && !explicit_session && program_index + 1 < argc) {
			const wchar_t *value = arguments[++program_index];
			if (!value[0] || wcsspn(value, L"0123456789") != wcslen(value)) goto usage;
			errno = 0;
			session = wcstoul(value, &end, 10);
			if (errno || *end || !session || session == 0xffffffffUL) goto usage;
			explicit_session = 1;
		} else if (!wcscmp(arguments[program_index], L"--expect-user") && !expected_user && program_index + 1 < argc) {
			expected_user = arguments[++program_index];
			if (!expected_user[0]) goto usage;
		} else goto usage;
		program_index++;
	}
	if (program_index >= argc || !arguments[program_index][0]) {
usage:
		fputs("Usage: dropbear-win.exe --desktop-launch [--session ID] [--expect-user [DOMAIN\\]user] C:\\absolute\\program.exe [arguments...]\n"
			"Session ID must be a nonzero logged-on console/RDP session; this does not create a Windows login.\n", stderr);
		goto done;
	}
	/* Do not search the SYSTEM service's PATH or resolve relative to its cwd. */
	if (wcslen(arguments[program_index]) < 3 ||
			!((arguments[program_index][0] >= L'A' && arguments[program_index][0] <= L'Z') ||
			(arguments[program_index][0] >= L'a' && arguments[program_index][0] <= L'z')) ||
			arguments[program_index][1] != L':' ||
			(arguments[program_index][2] != L'\\' && arguments[program_index][2] != L'/')) {
		fputs("Desktop launch requires a drive-absolute executable path.\n", stderr);
		goto done;
	}
	length = GetFullPathNameW(arguments[program_index], 32768, executable, NULL);
	if (!length || length >= 32768) {
		fputs("Could not normalize the desktop executable path.\n", stderr);
		goto done;
	}
	attributes = GetFileAttributesW(executable);
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
		fputs("Desktop executable does not exist or is a directory.\n", stderr);
		goto done;
	}
	line = calloc(32768, sizeof(*line));
	if (!line || !exec_argument(line, &used, executable)) goto done;
	for (i = program_index + 1; i < argc; i++) if (!exec_argument(line, &used, arguments[i])) {
		fputs("Desktop command exceeds the Windows command-line limit.\n", stderr);
		goto done;
	}
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
			&process_token)) goto done;
	for (i = 0; i < 3; i++) {
		if (!LookupPrivilegeValueW(NULL, privilege_names[i], &luid)) goto done;
		memset(&privileges, 0, sizeof(privileges));
		privileges.PrivilegeCount = 1;
		privileges.Privileges[0].Luid = luid;
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		SetLastError(ERROR_SUCCESS);
		if (!AdjustTokenPrivileges(process_token, FALSE, &privileges, 0, NULL, NULL) ||
				GetLastError() != ERROR_SUCCESS) {
			fputs("Could not enable desktop launch privileges.\n", stderr);
			goto done;
		}
	}
	if (!explicit_session) session = active_session();
	if (session == 0xffffffffUL) {
		fputs("No active console session is available.\n", stderr);
		goto done;
	}
	if (!query_session(NULL, session, WTSConnectState, (LPWSTR *)&session_state, &returned) ||
			returned < sizeof(*session_state) ||
			(*session_state != WTSActive && *session_state != WTSConnected)) {
		fputs("Target session must be active/connected and have a logged-on user. Inspect query session first.\n", stderr);
		goto done;
	}
	if (!query_user_token(session, &token)) {
		fprintf(stderr, "No logged-on user is available in session %lu: Windows error %lu. Use --session ID for an existing RDP login.\n",
			(unsigned long)session, (unsigned long)GetLastError());
		goto done;
	}
	if (!GetTokenInformation(token, TokenSessionId, &actual_session, sizeof(actual_session), &returned) ||
			actual_session != session) {
		fputs("Target token session does not match requested session.\n", stderr); goto done;
	}
	GetTokenInformation(token, TokenUser, NULL, 0, &token_size);
	token_user = token_size ? calloc(1, token_size) : NULL;
	if (!token_user || !GetTokenInformation(token, TokenUser, token_user, token_size, &returned) ||
			!LookupAccountSidW(NULL, token_user->User.Sid, name, &name_size, domain, &domain_size, &sid_use)) {
		fputs("Could not verify target session Windows identity.\n", stderr); goto done;
	}
	_snwprintf(identity, 520, L"%ls%ls%ls", domain, domain[0] ? L"\\" : L"", name);
	if (expected_user && _wcsicmp(expected_user, wcschr(expected_user, L'\\') ? identity : name)) {
		fputs("Target session user does not match --expect-user; no process was started.\n", stderr); goto done;
	}
	if (!WideCharToMultiByte(CP_UTF8, 0, identity, -1, identity_utf8, sizeof(identity_utf8), NULL, NULL)) goto done;
	if (!create_environment(&environment, token, FALSE)) {
		fprintf(stderr, "Could not build the desktop user's environment: Windows error %lu.\n",
			(unsigned long)GetLastError());
		goto done;
	}
	wcscpy(directory, executable);
	slash = wcsrchr(directory, L'\\');
	if (!slash) goto done;
	*slash = 0;
	memset(&startup, 0, sizeof(startup));
	memset(&process, 0, sizeof(process));
	startup.cb = sizeof(startup);
	startup.lpDesktop = L"winsta0\\default";
	startup.dwFlags = STARTF_USESHOWWINDOW;
	startup.wShowWindow = SW_SHOWNORMAL;
	if (!CreateProcessAsUserW(token, executable, line, NULL, NULL, FALSE,
			CREATE_BREAKAWAY_FROM_JOB | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
			environment, directory, &startup, &process)) {
		error = GetLastError();
		fprintf(stderr, "Desktop process startup failed: Windows error %lu.\n",
			(unsigned long)error);
		goto done;
	}
	/* A successful CreateProcess call precedes DLL/console initialization. Report
	 * immediate startup failures instead of claiming a healthy desktop process. */
	if (WaitForSingleObject(process.hProcess, 500) == WAIT_OBJECT_0) {
		DWORD exit_code = ERROR_GEN_FAILURE;
		if (!GetExitCodeProcess(process.hProcess, &exit_code) || exit_code) {
			fprintf(stderr, "Desktop process exited during startup: PID %lu, Windows exit code %lu.\n",
				(unsigned long)process.dwProcessId, (unsigned long)exit_code);
			CloseHandle(process.hThread); CloseHandle(process.hProcess); goto done;
		}
	}
	printf("Desktop process started: PID %lu, session %lu, user %s, desktop winsta0\\default (user token; SYSTEM not retained).\n",
		(unsigned long)process.dwProcessId, (unsigned long)session, identity_utf8);
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	result = 0;
done:
	free(token_user);
	if (session_state && wts_free) wts_free(session_state);
	if (process_token) CloseHandle(process_token);
	if (environment && destroy_environment) destroy_environment(environment);
	if (token) CloseHandle(token);
	if (arguments) LocalFree(arguments);
	free(line);
	if (userenv) FreeLibrary(userenv);
	if (wts) FreeLibrary(wts);
	if (shell32) FreeLibrary(shell32);
	return result;
}

int dropbear_win_exec_main(void) {
	char magic[4];
	unsigned int count, i;
	wchar_t *program = NULL, *cwd = NULL, *name = NULL, *value = NULL;
	wchar_t *line = calloc(32768, sizeof(*line));
	size_t used = 0;
	STARTUPINFOW startup;
	PROCESS_INFORMATION process;
	DWORD status = 125;
	int started = 0;
	exec_budget = 1024 * 1024 - 4;
	if (!line || !exec_read(magic, 4) ||
		(memcmp(magic, "DBX1", 4) && memcmp(magic, "DBX2", 4))) goto done;
	exec_base64 = !memcmp(magic, "DBX2", 4);
	program = exec_field(); cwd = exec_field();
	if (!program || !program[0] || !cwd || !exec_number(&count) || count > 256) goto done;
	/* This helper is a dedicated child; overrides never affect another channel. */
	for (i = 0; i < count; i++) {
		name = exec_field(); value = exec_field();
		if (!name || !name[0] || wcschr(name, L'=') || !value ||
			!SetEnvironmentVariableW(name, value)) goto done;
		free(name); name = NULL; free(value); value = NULL;
	}
	if (!exec_number(&count) || count > 4096 || !exec_argument(line, &used, program)) goto done;
	for (i = 0; i < count; i++) {
		value = exec_field();
		if (!value || !exec_argument(line, &used, value)) goto done;
		free(value); value = NULL;
	}
	memset(&startup, 0, sizeof(startup));
	startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
	startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	if (!CreateProcessW(program, line, NULL, NULL, TRUE, CREATE_NO_WINDOW,
		NULL, cwd[0] ? cwd : NULL, &startup, &process)) {
		fprintf(stderr, "dropbear-exec: CreateProcessW error %lu\n", (unsigned long)GetLastError());
		goto done;
	}
	CloseHandle(process.hThread);
	started = 1;
	WaitForSingleObject(process.hProcess, INFINITE);
	GetExitCodeProcess(process.hProcess, &status);
	CloseHandle(process.hProcess);
done:
	if (!started) fputs("dropbear-exec: invalid request or execution failure\n", stderr);
	free(program); free(cwd); free(name); free(value); free(line);
	return (int)status;
}

struct bridge_context {
	int socket_fd;
	HANDLE pipe_handle;
	int socket_to_pipe;
	UINT source_codepage;
	UINT target_codepage;
	unsigned char pending[4];
	unsigned int pending_length;
};

static struct process_entry processes[256];
static CRITICAL_SECTION process_lock;
static dropbear_win_once process_once = DROPBEAR_WIN_ONCE_INIT;

static int init_process_table(void) {
	InitializeCriticalSection(&process_lock);
	return 1;
}

static void ensure_process_table(void) {
	dropbear_win_once_run(&process_once, init_process_table);
}

int dropbear_win_random(void *buffer, unsigned int length) {
	typedef BOOLEAN (APIENTRY *rtl_gen_random_fn)(PVOID, ULONG);
	HCRYPTPROV provider = 0;
	BOOL ok = FALSE;
	HMODULE advapi;
	rtl_gen_random_fn rtl_gen_random;
	if (!buffer && length) return -1;
	if (CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		ok = CryptGenRandom(provider, length, (BYTE *)buffer);
		CryptReleaseContext(provider, 0);
		if (ok) return 0;
	}
	advapi = GetModuleHandleA("advapi32.dll");
	rtl_gen_random = advapi
		? (rtl_gen_random_fn)(void *)GetProcAddress(advapi, "SystemFunction036") : NULL;
	return rtl_gen_random && rtl_gen_random(buffer, length) ? 0 : -1;
}

int dropbear_win_gettimeofday(struct timeval *tv, void *timezone) {
	FILETIME filetime;
	ULARGE_INTEGER value;
	(void)timezone;
	if (!tv) return -1;
	GetSystemTimeAsFileTime(&filetime);
	value.LowPart = filetime.dwLowDateTime;
	value.HighPart = filetime.dwHighDateTime;
	value.QuadPart -= 116444736000000000ULL;
	tv->tv_sec = (long)(value.QuadPart / 10000000ULL);
	tv->tv_usec = (long)((value.QuadPart % 10000000ULL) / 10ULL);
	return 0;
}

static int bridge_write(struct bridge_context *context,
		const unsigned char *buffer, unsigned int length) {
	unsigned int offset = 0;
	while (offset < length) {
		if (context->socket_to_pipe) {
			DWORD written = 0;
			if (!WriteFile(context->pipe_handle, buffer + offset,
					length - offset, &written, NULL) || written == 0) return 0;
			offset += written;
		} else {
			int written = dropbear_win_write(context->socket_fd,
				buffer + offset, length - offset);
			if (written <= 0) return 0;
			offset += (unsigned int)written;
		}
	}
	return 1;
}

static unsigned int incomplete_character_length(UINT codepage,
		const unsigned char *buffer, unsigned int length) {
	if (!length) return 0;
	if (codepage == CP_UTF8) {
		unsigned int start = length - 1;
		unsigned int expected = 0;
		while (start > 0 && (buffer[start] & 0xc0) == 0x80 && length - start < 4) start--;
		if ((buffer[start] & 0x80) == 0) expected = 1;
		else if ((buffer[start] & 0xe0) == 0xc0) expected = 2;
		else if ((buffer[start] & 0xf0) == 0xe0) expected = 3;
		else if ((buffer[start] & 0xf8) == 0xf0) expected = 4;
		if (expected > length - start) return length - start;
		return 0;
	}
	if (IsDBCSLeadByteEx(codepage, buffer[length - 1])) return 1;
	return 0;
}

static int bridge_transcode(struct bridge_context *context,
		const unsigned char *input, unsigned int input_length, int final) {
	unsigned char combined[8192 + 4];
	wchar_t wide[8192 + 4];
	unsigned char output[(8192 + 4) * 4];
	unsigned int total = context->pending_length + input_length;
	unsigned int trailing;
	unsigned int convert_length;
	int wide_length;
	int output_length;

	if (total > sizeof(combined)) return 0;
	memcpy(combined, context->pending, context->pending_length);
	if (input_length) memcpy(combined + context->pending_length, input, input_length);
	trailing = final ? 0 : incomplete_character_length(context->source_codepage, combined, total);
	convert_length = total - trailing;
	context->pending_length = trailing;
	if (trailing) memcpy(context->pending, combined + convert_length, trailing);
	if (!convert_length) return 1;

	wide_length = MultiByteToWideChar(context->source_codepage, 0,
		(const char *)combined, convert_length, wide,
		sizeof(wide) / sizeof(wide[0]));
	if (wide_length <= 0) return 0;
	output_length = WideCharToMultiByte(context->target_codepage, 0,
		wide, wide_length, (char *)output, sizeof(output), NULL, NULL);
	if (output_length <= 0) return 0;
	return bridge_write(context, output, (unsigned int)output_length);
}

static int bridge_forward(struct bridge_context *context,
		const unsigned char *buffer, unsigned int length) {
	if (!context->source_codepage || !context->target_codepage ||
			context->source_codepage == context->target_codepage) {
		return bridge_write(context, buffer, length);
	}
	return bridge_transcode(context, buffer, length, 0);
}

static unsigned __stdcall bridge_thread(void *userdata) {
	struct bridge_context *context = userdata;
	unsigned char buffer[8192];
	for (;;) {
		if (context->socket_to_pipe) {
			int count = dropbear_win_read(context->socket_fd, buffer, sizeof(buffer));
			if (count <= 0 || !bridge_forward(context, buffer, (unsigned int)count)) break;
		} else {
			DWORD count = 0;
			if (!ReadFile(context->pipe_handle, buffer, sizeof(buffer), &count, NULL) ||
					count == 0 || !bridge_forward(context, buffer, count)) break;
		}
	}
	if (context->pending_length) bridge_transcode(context, NULL, 0, 1);
	CloseHandle(context->pipe_handle);
	dropbear_win_shutdown(context->socket_fd, SD_BOTH);
	dropbear_win_close(context->socket_fd);
	HeapFree(GetProcessHeap(), 0, context);
	return 0;
}

static int start_bridge(int worker_fd, HANDLE pipe_handle, int socket_to_pipe,
		UINT source_codepage, UINT target_codepage) {
	struct bridge_context *context;
	uintptr_t thread;
	context = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*context));
	if (!context) return -1;
	context->socket_fd = worker_fd;
	context->pipe_handle = pipe_handle;
	context->socket_to_pipe = socket_to_pipe;
	context->source_codepage = source_codepage;
	context->target_codepage = target_codepage;
	thread = _beginthreadex(NULL, 0, bridge_thread, context, 0, NULL);
	if (!thread) {
		HeapFree(GetProcessHeap(), 0, context);
		return -1;
	}
	CloseHandle((HANDLE)thread);
	return 0;
}

static wchar_t *utf8_to_wide(const char *text) {
	int count;
	wchar_t *wide;
	if (!text) text = "";
	count = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
	if (count <= 0) return NULL;
	wide = HeapAlloc(GetProcessHeap(), 0, count * sizeof(*wide));
	if (!wide) return NULL;
	if (!MultiByteToWideChar(CP_UTF8, 0, text, -1, wide, count)) {
		HeapFree(GetProcessHeap(), 0, wide);
		return NULL;
	}
	return wide;
}

static int legacy_scp_command(const char *command) {
	const char *p = command;
	int server_mode = 0;
	if (!p) return 0;
	while (*p == ' ' || *p == '\t') p++;
	if (strncmp(p, "scp", 3) != 0 || (p[3] != ' ' && p[3] != '\t')) return 0;
	p += 3;
	while (*p) {
		while (*p == ' ' || *p == '\t') p++;
		if (*p != '-') break;
		p++;
		while (*p && *p != ' ' && *p != '\t') {
			if (*p == 'f' || *p == 't') server_mode = 1;
			p++;
		}
	}
	return server_mode;
}

/* Service registration needs the SCM command line in the exact shape
 * dropbear_win_service_main parses: "exe" --service <name> <original args>. */
wchar_t *dropbear_win_build_service_command_line(const wchar_t *executable,
		int argc, char **argv) {
	wchar_t *line = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
		32768 * sizeof(*line));
	size_t used;
	int i;
	if (!line) return NULL;
	used = (size_t)_snwprintf(line, 32768, L"\"%ls\"", executable);
	if (used >= 32768) goto fail;
	if (!exec_argument(line, &used, L"--service") ||
			!exec_argument(line, &used, L"DropbearWin")) goto fail;
	for (i = 1; i < argc; i++) {
		wchar_t *argument = utf8_to_wide(argv[i]);
		int ok = argument && exec_argument(line, &used, argument);
		if (argument) HeapFree(GetProcessHeap(), 0, argument);
		if (!ok) goto fail;
	}
	return line;
fail:
	HeapFree(GetProcessHeap(), 0, line);
	return NULL;
}

/* Relaunch only the installer with an elevation-attempt marker. All original
 * server options are retained with the same CRT quoting as service startup. */
wchar_t *dropbear_win_build_autostart_relaunch_parameters(int argc, char **argv) {
	wchar_t *line = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
		32768 * sizeof(*line));
	size_t used = 0;
	int i;
	if (!line) return NULL;
	if (!exec_argument(line, &used, L"--install-autostart-elevated")) goto fail;
	for (i = 2; i < argc; i++) {
		wchar_t *argument = utf8_to_wide(argv[i]);
		int ok = argument && exec_argument(line, &used, argument);
		if (argument) HeapFree(GetProcessHeap(), 0, argument);
		if (!ok) goto fail;
	}
	return line;
fail:
	HeapFree(GetProcessHeap(), 0, line);
	return NULL;
}

static wchar_t *make_internal_command_line(const wchar_t *executable,
		const wchar_t *mode, const char *payload) {
	size_t executable_length = wcslen(executable);
	size_t payload_length = payload ? strlen(payload) : 0;
	size_t capacity = executable_length + wcslen(mode) + payload_length * 2 + 16;
	wchar_t *line = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
		capacity * sizeof(*line));
	size_t used;
	size_t i;
	static const wchar_t hex[] = L"0123456789abcdef";
	if (!line) return NULL;
	used = (size_t)_snwprintf(line, capacity, L"\"%ls\" %ls", executable, mode);
	if (payload) {
		line[used++] = L' ';
		for (i = 0; i < payload_length; i++) {
			unsigned char value = (unsigned char)payload[i];
			line[used++] = hex[value >> 4];
			line[used++] = hex[value & 15];
		}
		line[used] = L'\0';
	}
	return line;
}

static VOID CALLBACK notify_process_exit(PVOID context, BOOLEAN timed_out) {
	struct process_entry *entry = context;
	const char byte = 1;
	(void)timed_out;
	/* Only wake the session loop. It owns reaping, channel state and jobs.
	 * The pipe is nonblocking; a full pipe already guarantees a wakeup. */
	dropbear_win_write(entry->notify_fd, &byte, 1);
}

static int register_process(HANDLE process, DWORD pid, HANDLE job) {
	unsigned int i;
	ensure_process_table();
	EnterCriticalSection(&process_lock);
	for (i = 0; i < sizeof(processes) / sizeof(processes[0]); i++) {
		if (!processes[i].process) {
			processes[i].process = process;
			processes[i].pid = pid;
			processes[i].job = job;
			if (job) {
				processes[i].notify_fd = ses.signal_pipe[1];
				if (!RegisterWaitForSingleObject(&processes[i].exit_wait, process,
					notify_process_exit, &processes[i], INFINITE, WT_EXECUTEONLYONCE)) {
					memset(&processes[i], 0, sizeof(processes[i]));
					LeaveCriticalSection(&process_lock);
					return -1;
				}
			}
			LeaveCriticalSection(&process_lock);
			return 0;
		}
	}
	LeaveCriticalSection(&process_lock);
	return -1;
}

static void wide_to_utf8(const wchar_t *wide, char *utf8, size_t utf8_size) {
	if (!utf8 || utf8_size == 0) return;
	utf8[0] = '\0';
	if (!wide || !WideCharToMultiByte(CP_UTF8, 0, wide, -1,
			utf8, (int)utf8_size, NULL, NULL)) utf8[0] = '\0';
}

static void sanitize_motd_value(const char *input, char *output, size_t output_size) {
	size_t i = 0;
	if (!output || output_size == 0) return;
	if (!input) input = "";
	while (*input && i + 1 < output_size) {
		unsigned char c = (unsigned char)*input++;
		output[i++] = (c >= 32 && c != 127) ? (char)c : '?';
	}
	output[i] = '\0';
}

static void append_motd(char *buffer, size_t buffer_size, size_t *used,
		const char *format, ...) {
	va_list args;
	int count;
	if (*used >= buffer_size) return;
	va_start(args, format);
	count = vsnprintf(buffer + *used, buffer_size - *used, format, args);
	va_end(args);
	if (count < 0) return;
	if ((size_t)count >= buffer_size - *used) *used = buffer_size - 1;
	else *used += (size_t)count;
}

static const char *native_architecture(void) {
	SYSTEM_INFO info;
	GetNativeSystemInfo(&info);
	switch (info.wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
		case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
#ifdef PROCESSOR_ARCHITECTURE_ARM64
		case PROCESSOR_ARCHITECTURE_ARM64: return "ARM64";
#endif
		case PROCESSOR_ARCHITECTURE_ARM: return "ARM";
		default: return "unknown architecture";
	}
}

static void windows_version(char *output, size_t output_size) {
	typedef LONG (WINAPI *rtl_get_version_fn)(OSVERSIONINFOW *);
	OSVERSIONINFOW version;
	rtl_get_version_fn rtl_get_version;
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	memset(&version, 0, sizeof(version));
	version.dwOSVersionInfoSize = sizeof(version);
	rtl_get_version = ntdll
		? (rtl_get_version_fn)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
	if (rtl_get_version && rtl_get_version(&version) == 0) {
		snprintf(output, output_size, "Windows NT %lu.%lu build %lu (%s)",
			(unsigned long)version.dwMajorVersion,
			(unsigned long)version.dwMinorVersion,
			(unsigned long)version.dwBuildNumber, native_architecture());
	} else {
		snprintf(output, output_size, "Windows (%s)", native_architecture());
	}
}

static const char *integrity_name(DWORD integrity) {
	if (integrity == 0) return "integrity unavailable";
	if (integrity >= SECURITY_MANDATORY_SYSTEM_RID) return "System";
	if (integrity >= SECURITY_MANDATORY_HIGH_RID) return "High";
	if (integrity >= SECURITY_MANDATORY_MEDIUM_RID) return "Medium";
	if (integrity >= SECURITY_MANDATORY_LOW_RID) return "Low";
	return "Untrusted";
}

static void token_status(char *output, size_t output_size) {
	HANDLE token = NULL;
	TOKEN_ELEVATION elevation;
	DWORD returned = 0;
	DWORD label_size = 0;
	DWORD integrity = 0;
	BOOL elevated = FALSE;
	BOOL administrator = FALSE;
	PSID admin_sid = NULL;
	TOKEN_MANDATORY_LABEL *label = NULL;
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		if (GetTokenInformation(token, TokenElevation, &elevation,
				sizeof(elevation), &returned)) elevated = elevation.TokenIsElevated;
		GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &label_size);
		if (label_size) {
			label = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, label_size);
			if (label && GetTokenInformation(token, TokenIntegrityLevel,
					label, label_size, &returned)) {
				PSID sid = label->Label.Sid;
				DWORD count = *GetSidSubAuthorityCount(sid);
				if (count) integrity = *GetSidSubAuthority(sid, count - 1);
			}
		}
	}
	if (AllocateAndInitializeSid(&nt_authority, 2,
			SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0, &admin_sid)) {
		CheckTokenMembership(NULL, admin_sid, &administrator);
		FreeSid(admin_sid);
	}
	if (integrity >= SECURITY_MANDATORY_SYSTEM_RID) {
		snprintf(output, output_size, "System token (%s integrity)", integrity_name(integrity));
	} else if (elevated && administrator) {
		snprintf(output, output_size, "Elevated administrator (%s integrity)",
			integrity_name(integrity));
	} else if (administrator) {
		snprintf(output, output_size, "Administrator (%s integrity)", integrity_name(integrity));
	} else {
		snprintf(output, output_size, "%s (%s integrity)",
			elevated ? "Elevated token" : "Standard/non-elevated token",
			integrity_name(integrity));
	}
	if (label) HeapFree(GetProcessHeap(), 0, label);
	if (token) CloseHandle(token);
}

void dropbear_win_runtime_security(char *identity, size_t identity_size,
		char *token_text, size_t token_size, DWORD *session_id) {
	HANDLE process_token = NULL;
	TOKEN_USER *token_user = NULL;
	PSID system_sid = NULL;
	DWORD token_user_size = 0;
	DWORD name_size = 256, domain_size = 256;
	wchar_t name[256], domain[256], combined[520];
	SID_NAME_USE sid_type;
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
	int local_system = 0;

	if (identity && identity_size) snprintf(identity, identity_size, "unknown");
	if (token_text && token_size) token_status(token_text, token_size);
	if (session_id && !ProcessIdToSessionId(GetCurrentProcessId(), session_id))
		*session_id = 0xffffffffUL;
	if (!identity || !identity_size ||
			!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &process_token)) goto done;
	GetTokenInformation(process_token, TokenUser, NULL, 0, &token_user_size);
	if (!token_user_size) goto done;
	token_user = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, token_user_size);
	if (!token_user || !GetTokenInformation(process_token, TokenUser, token_user,
			token_user_size, &token_user_size)) goto done;
	if (AllocateAndInitializeSid(&nt_authority, 1, SECURITY_LOCAL_SYSTEM_RID,
			0, 0, 0, 0, 0, 0, 0, &system_sid))
		local_system = EqualSid(token_user->User.Sid, system_sid);
	if (local_system) {
		snprintf(identity, identity_size, "NT AUTHORITY\\SYSTEM");
		if (token_text && token_size)
			snprintf(token_text, token_size,
				"LocalSystem / full SYSTEM (System integrity; NOT an elevated Administrator token)");
		goto done;
	}
	if (!LookupAccountSidW(NULL, token_user->User.Sid, name, &name_size,
			domain, &domain_size, &sid_type)) goto done;
	if (domain[0]) _snwprintf(combined, sizeof(combined) / sizeof(combined[0]),
		L"%ls\\%ls", domain, name);
	else _snwprintf(combined, sizeof(combined) / sizeof(combined[0]), L"%ls", name);
	wide_to_utf8(combined, identity, identity_size);
done:
	if (system_sid) FreeSid(system_sid);
	if (token_user) HeapFree(GetProcessHeap(), 0, token_user);
	if (process_token) CloseHandle(process_token);
}

static int write_session_motd(int output_fd, const wchar_t *shell,
		const char *ssh_user, const char *terminal, const char *connection) {
	char motd[8192];
	char resources[1024];
	char hostname[512] = "unknown";
	char identity[1050];
	char executable_path[MAX_PATH * 3] = "dropbear-win.exe";
	char shell_utf8[MAX_PATH * 3];
	char cwd[MAX_PATH * 3] = "unknown";
	char os[160];
	char token[160];
	char codepage_name[256] = "Windows OEM encoding";
	char safe_ssh_user[256];
	char safe_executable[MAX_PATH * 3];
	char safe_terminal[256];
	char safe_connection[512];
	wchar_t wide_buffer[MAX_PATH];
	DWORD wide_size, session_id = 0xffffffffUL;
	CPINFOEXW codepage_info;
	size_t used = 0;

	wide_size = sizeof(wide_buffer) / sizeof(wide_buffer[0]);
	if (GetComputerNameW(wide_buffer, &wide_size)) wide_to_utf8(wide_buffer, hostname, sizeof(hostname));
	wide_size = GetModuleFileNameW(NULL, wide_buffer,
		sizeof(wide_buffer) / sizeof(wide_buffer[0]));
	if (wide_size && wide_size < sizeof(wide_buffer) / sizeof(wide_buffer[0]))
		wide_to_utf8(wide_buffer, executable_path, sizeof(executable_path));
	wide_to_utf8(shell, shell_utf8, sizeof(shell_utf8));
	if (GetCurrentDirectoryW(sizeof(wide_buffer) / sizeof(wide_buffer[0]), wide_buffer))
		wide_to_utf8(wide_buffer, cwd, sizeof(cwd));
	windows_version(os, sizeof(os));
	dropbear_win_runtime_security(identity, sizeof(identity), token, sizeof(token), &session_id);
	memset(&codepage_info, 0, sizeof(codepage_info));
	if (GetCPInfoExW(GetOEMCP(), 0, &codepage_info))
		wide_to_utf8(codepage_info.CodePageName, codepage_name, sizeof(codepage_name));
	sanitize_motd_value(ssh_user, safe_ssh_user, sizeof(safe_ssh_user));
	sanitize_motd_value(executable_path, safe_executable, sizeof(safe_executable));
	sanitize_motd_value(terminal, safe_terminal, sizeof(safe_terminal));
	sanitize_motd_value(connection, safe_connection, sizeof(safe_connection));

	append_motd(motd, sizeof(motd), &used, "\r\n============================================================\r\n");
	append_motd(motd, sizeof(motd), &used, " Welcome to Dropbear for Windows\r\n");
	append_motd(motd, sizeof(motd), &used, "------------------------------------------------------------\r\n");
	append_motd(motd, sizeof(motd), &used, " Host:         %s\r\n", hostname);
	append_motd(motd, sizeof(motd), &used, " System:       %s\r\n", os);
	append_motd(motd, sizeof(motd), &used, " Binary:       %s\r\n",
		dropbear_win_binary_architecture());
	append_motd(motd, sizeof(motd), &used, " Compatibility: %s\r\n",
		dropbear_win_compatibility_profile());
	append_motd(motd, sizeof(motd), &used,
		" Security context below is authoritative for ordinary SSH commands:\r\n");
	append_motd(motd, sizeof(motd), &used,
		" SSH user:     %s (Dropbear authentication only; NOT a Windows account)\r\n",
		safe_ssh_user[0] ? safe_ssh_user : "unknown");
	append_motd(motd, sizeof(motd), &used, " Windows user: %s (effective command identity)\r\n", identity);
	append_motd(motd, sizeof(motd), &used, " Access token: %s\r\n", token);
	append_motd(motd, sizeof(motd), &used, " Session ID:   %lu (%s)\r\n",
		(unsigned long)session_id,
		session_id == 0xffffffffUL ? "unavailable" :
			(session_id == 0 ? "service/non-interactive" : "interactive or user session"));
	append_motd(motd, sizeof(motd), &used,
		" Command rule: ordinary SSH commands inherit the Windows user/token above and remain in this session.\r\n");
	append_motd(motd, sizeof(motd), &used,
		" Agent guide:  from the client run: ssh user@host __dropbear_win_guide__\r\n");
	append_motd(motd, sizeof(motd), &used,
		" Desktop GUI:  \"%s\" --desktop-launch [--session ID] [--expect-user USER] \"C:\\absolute\\program.exe\" [args]\r\n",
		safe_executable);
	if (!strcmp(identity, "NT AUTHORITY\\SYSTEM")) {
		append_motd(motd, sizeof(motd), &used,
			" Permission switch: GUI uses the selected logged-on user's primary token/environment; SSH SYSTEM is NOT retained.\r\n");
	} else {
		append_motd(motd, sizeof(motd), &used,
			" Permission switch: --desktop-launch is intended for an installed LocalSystem service; this SSH token is not SYSTEM.\r\n");
	}
	append_motd(motd, sizeof(motd), &used,
		" Session target: default physical console; --session ID selects an active/connected console or RDP login. No new login is created.\r\n");
	append_motd(motd, sizeof(motd), &used, " Shell:        %s\r\n", shell_utf8);
	append_motd(motd, sizeof(motd), &used, " Terminal:     %s (%s)\r\n",
		safe_terminal[0] ? safe_terminal : "not requested",
		safe_terminal[0] ? "PTY requested; native pipe transport" : "native SSH stream");
	append_motd(motd, sizeof(motd), &used, " Connection:   %s\r\n",
		safe_connection[0] ? safe_connection : "unknown");
	append_motd(motd, sizeof(motd), &used, " Working dir:  %s\r\n", cwd);
	dropbear_win_resource_summary(resources, sizeof(resources));
	append_motd(motd, sizeof(motd), &used, "------------------------------------------------------------\r\n%s", resources);
	append_motd(motd, sizeof(motd), &used, "------------------------------------------------------------\r\n");
	append_motd(motd, sizeof(motd), &used, " Code pages:   ANSI %u, OEM %u\r\n",
		(unsigned int)GetACP(), (unsigned int)GetOEMCP());
	if (wcsstr(shell, L"powershell.exe")) {
		append_motd(motd, sizeof(motd), &used, " Encoding mode: raw pipes; script/application determines text encoding\r\n");
	} else if (wcsstr(shell, L"cmd.exe")) {
	append_motd(motd, sizeof(motd), &used, " Encoding mode: interactive terminal text conversion is enabled\r\n");
	append_motd(motd, sizeof(motd), &used, " Client text:  UTF-8\r\n");
	append_motd(motd, sizeof(motd), &used, " CMD encoding: cmd.exe is currently using code page %u (%s)\r\n",
		(unsigned int)GetOEMCP(), codepage_name);
	append_motd(motd, sizeof(motd), &used, " Input path:   client UTF-8 is converted to cmd code page %u\r\n",
		(unsigned int)GetOEMCP());
	append_motd(motd, sizeof(motd), &used, " Output path:  cmd code page %u is converted to client UTF-8\r\n",
		(unsigned int)GetOEMCP());
	append_motd(motd, sizeof(motd), &used, " MOTD charset: transmitted as UTF-8; identical on both ends\r\n");
	} else {
	append_motd(motd, sizeof(motd), &used, " Encoding mode: interactive terminal text conversion is enabled\r\n");
	append_motd(motd, sizeof(motd), &used, " Client text:  UTF-8\r\n");
	append_motd(motd, sizeof(motd), &used, " Shell text:   code page %u (%s)\r\n",
		(unsigned int)GetOEMCP(), codepage_name);
	append_motd(motd, sizeof(motd), &used, " Input path:   client UTF-8 is converted to shell code page %u\r\n",
		(unsigned int)GetOEMCP());
	append_motd(motd, sizeof(motd), &used, " Output path:  shell code page %u is converted to client UTF-8\r\n",
		(unsigned int)GetOEMCP());
	}
	append_motd(motd, sizeof(motd), &used, " Raw mode:     commands without a PTY keep original bytes; no text conversion\r\n");
	append_motd(motd, sizeof(motd), &used, "============================================================\r\n\r\n");
	return dropbear_win_write(output_fd, motd, (unsigned int)used) == (int)used;
}

/* Snapshot an independent Unicode environment for each channel. The session
 * process may have several live channels; never mutate its global environment. */
static wchar_t *session_environment(const char *user, const char *term,
		const char *connection, const wchar_t *shell) {
	wchar_t *inherited = GetEnvironmentStringsW(), *p, *result, *out;
	wchar_t *wide_user = utf8_to_wide(user), *wide_term = utf8_to_wide(term);
	wchar_t *wide_connection = utf8_to_wide(connection);
	wchar_t cwd[MAX_PATH];
	size_t capacity = 2;
	if (!inherited || !wide_user || !wide_term || !wide_connection ||
		!GetCurrentDirectoryW(MAX_PATH, cwd)) goto fail;
	for (p = inherited; *p; p += wcslen(p) + 1) capacity += wcslen(p) + 1;
	capacity += wcslen(wide_user) * 2 + wcslen(wide_term) +
		wcslen(wide_connection) * 2 + wcslen(shell) + wcslen(cwd) + 160;
	result = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, capacity * sizeof(*result));
	if (!result) goto fail;
	out = result;
	for (p = inherited; *p; p += wcslen(p) + 1) {
		if (!_wcsnicmp(p, L"USER=", 5) || !_wcsnicmp(p, L"LOGNAME=", 8) ||
			!_wcsnicmp(p, L"HOME=", 5) || !_wcsnicmp(p, L"SHELL=", 6) ||
			!_wcsnicmp(p, L"TERM=", 5) || !_wcsnicmp(p, L"SSH_CONNECTION=", 15) ||
			!_wcsnicmp(p, L"SSH_CLIENT=", 11)) continue;
		wcscpy(out, p); out += wcslen(out) + 1;
	}
#define SESSION_ENV(name, value) do { wcscpy(out, name L"="); wcscat(out, value); out += wcslen(out) + 1; } while (0)
	SESSION_ENV(L"USER", wide_user);
	SESSION_ENV(L"LOGNAME", wide_user);
	SESSION_ENV(L"HOME", cwd);
	SESSION_ENV(L"SHELL", shell);
	SESSION_ENV(L"TERM", wide_term);
	SESSION_ENV(L"SSH_CONNECTION", wide_connection);
	/* remote address, remote port, local port */
	{
		wchar_t *a = wcschr(wide_connection, L' ');
		wchar_t *b = a ? wcschr(a + 1, L' ') : NULL;
		wchar_t *c = b ? wcschr(b + 1, L' ') : NULL;
		if (b && c) { memmove(b + 1, c + 1, (wcslen(c + 1) + 1) * sizeof(*b)); }
		SESSION_ENV(L"SSH_CLIENT", wide_connection);
	}
#undef SESSION_ENV
	FreeEnvironmentStringsW(inherited);
	HeapFree(GetProcessHeap(), 0, wide_user);
	HeapFree(GetProcessHeap(), 0, wide_term);
	HeapFree(GetProcessHeap(), 0, wide_connection);
	return result;
fail:
	if (inherited) FreeEnvironmentStringsW(inherited);
	if (wide_user) HeapFree(GetProcessHeap(), 0, wide_user);
	if (wide_term) HeapFree(GetProcessHeap(), 0, wide_term);
	if (wide_connection) HeapFree(GetProcessHeap(), 0, wide_connection);
	return NULL;
}

int dropbear_win_spawn_shell(const char *command, const char *ssh_user,
		const char *terminal, const char *connection,
		int *writefd, int *readfd, int *errfd, pid_t *pid) {
	SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
	STARTUPINFOW startup;
	PROCESS_INFORMATION process;
	HANDLE stdin_read = NULL, stdin_write = NULL;
	HANDLE stdout_read = NULL, stdout_write = NULL;
	HANDLE stderr_read = NULL, stderr_write = NULL;
	HANDLE job = NULL;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits;
	int input_sockets[2] = {-1, -1};
	int output_sockets[2] = {-1, -1};
	int error_sockets[2] = {-1, -1};
	wchar_t system_dir[MAX_PATH];
	wchar_t windows_dir[MAX_PATH];
	wchar_t shell[MAX_PATH];
	wchar_t executable[MAX_PATH];
	const wchar_t *application = shell;
	wchar_t *wide_command = NULL;
	wchar_t *command_line = NULL;
	wchar_t *environment = NULL;
	size_t command_line_len;
	BOOL created;
	int internal_mode = 0;
	int powershell = 0;
	int transcode_terminal;
	UINT shell_codepage;

	memset(&startup, 0, sizeof(startup));
	memset(&process, 0, sizeof(process));
	startup.cb = sizeof(startup);
	startup.dwFlags = STARTF_USESTDHANDLES;
	if (getenv("DROPBEAR_WIN_TRACE_EXEC")) {
		HANDLE log_lock = dropbear_win_log_handle();
		DWORD log_wait = log_lock ? WaitForSingleObject(log_lock, 5000) : WAIT_FAILED;
		const unsigned char *p = (const unsigned char *)(command ? command : "");
		fprintf(stderr, "SSH exec (%lu bytes): ", (unsigned long)strlen((const char *)p));
		for (; *p; p++) {
			if (*p < 32 || *p >= 127 || *p == '\\') fprintf(stderr, "\\x%02x", *p);
			else fputc(*p, stderr);
		}
		fputc('\n', stderr);
		fflush(stderr);
		if (log_wait == WAIT_OBJECT_0 || log_wait == WAIT_ABANDONED) ReleaseMutex(log_lock);
	}

	if (!CreatePipe(&stdin_read, &stdin_write, &security, 0) ||
		!CreatePipe(&stdout_read, &stdout_write, &security, 0) ||
		!CreatePipe(&stderr_read, &stderr_write, &security, 0)) goto fail;
	SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);
	startup.hStdInput = stdin_read;
	startup.hStdOutput = stdout_write;
	startup.hStdError = stderr_write;

	if (command && (!strcmp(command, "__dropbear_win_sftp__") ||
		!strcmp(command, "__dropbear_win_exec__") || !strcmp(command, "__dropbear_win_probe__") ||
		!strcmp(command, "__dropbear_win_manifest__") || !strcmp(command, "__dropbear_win_skill__") ||
		!strcmp(command, "__dropbear_win_mcp__") ||
		!strcmp(command, "__dropbear_win_guide__"))) {
		if (!GetModuleFileNameW(NULL, executable, MAX_PATH)) goto fail;
		application = executable;
		command_line = make_internal_command_line(executable,
			!strcmp(command, "__dropbear_win_probe__") ? L"--dropbear-win-probe" :
			!strcmp(command, "__dropbear_win_manifest__") ? L"--dropbear-win-manifest" :
			!strcmp(command, "__dropbear_win_skill__") ? L"--dropbear-win-skill" :
			!strcmp(command, "__dropbear_win_mcp__") ? L"--dropbear-win-mcp" :
			!strcmp(command, "__dropbear_win_guide__") ? L"--dropbear-win-guide" :
			!strcmp(command, "__dropbear_win_exec__") ? L"--dropbear-win-exec" : L"--dropbear-win-sftp", NULL);
		internal_mode = 1;
	} else if (legacy_scp_command(command)) {
		if (!GetModuleFileNameW(NULL, executable, MAX_PATH)) goto fail;
		application = executable;
		command_line = make_internal_command_line(executable,
			L"--dropbear-win-scp", command);
		internal_mode = 1;
	} else {
		const char *backend = getenv("DROPBEAR_WIN_SHELL");
		powershell = backend && strcmp(backend, "powershell") == 0;
		if (backend && backend[0] && strcmp(backend, "cmd") && !powershell) {
			dropbear_win_logf("DROPBEAR_WIN_SHELL must be cmd or powershell\r\n");
			goto fail;
		}
		if (!GetSystemDirectoryW(system_dir, MAX_PATH)) goto fail;
		_snwprintf(shell, MAX_PATH, L"%ls\\cmd.exe", system_dir);
		if (powershell) {
			if (!GetWindowsDirectoryW(windows_dir, MAX_PATH)) goto fail;
			_snwprintf(shell, MAX_PATH,
				L"%ls\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", windows_dir);
			if (GetFileAttributesW(shell) == INVALID_FILE_ATTRIBUTES) goto fail;
		}
		wide_command = utf8_to_wide(command);
		if (!wide_command) goto fail;
		/* PowerShell consumes UTF-16LE base64 directly, without a CMD parser. */
		if (powershell && command && command[0]) {
			unsigned long encoded_size = ((wcslen(wide_command) * 2 + 2) / 3) * 4 + 1;
			char *encoded = malloc(encoded_size);
			wchar_t *encoded_wide;
			if (!encoded) goto fail;
			if (base64_encode((unsigned char *)wide_command, wcslen(wide_command) * 2,
				encoded, &encoded_size) != CRYPT_OK) { free(encoded); goto fail; }
			encoded[encoded_size] = '\0';
			encoded_wide = utf8_to_wide(encoded);
			free(encoded);
			if (!encoded_wide) goto fail;
			HeapFree(GetProcessHeap(), 0, wide_command);
			wide_command = encoded_wide;
		}
		command_line_len = wcslen(shell) + wcslen(wide_command) + 128;
		command_line = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
			command_line_len * sizeof(*command_line));
		if (!command_line) goto fail;
		if (wcsstr(shell, L"powershell.exe")) {
			_snwprintf(command_line, command_line_len, command && command[0]
				? L"\"%ls\" -NoLogo -NoProfile -NonInteractive -EncodedCommand %ls"
				: L"\"%ls\" -NoLogo -NoProfile", shell, wide_command);
		} else {
			_snwprintf(command_line, command_line_len, command && command[0]
				? L"\"%ls\" /d /s /c \"%ls\""
				: L"\"%ls\" /d /q", shell, wide_command);
		}
	}
	if (!command_line) goto fail;
	environment = session_environment(ssh_user, terminal, connection, internal_mode ? application : shell);
	if (!environment) goto fail;
	if (wcslen(command_line) >= 32767) {
		dropbear_win_logf("Remote command exceeds Windows command-line limit; use SFTP to upload a script.\r\n");
		goto fail;
	}
	job = CreateJobObjectW(NULL, NULL);
	memset(&job_limits, 0, sizeof(job_limits));
	/* Only explicit CREATE_BREAKAWAY_FROM_JOB launches leave the SSH task tree. */
	job_limits.BasicLimitInformation.LimitFlags =
		JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
	if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
		&job_limits, sizeof(job_limits))) goto fail;
	created = CreateProcessW(application, command_line, NULL, NULL, TRUE,
		CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
		environment, NULL, &startup, &process);
	HeapFree(GetProcessHeap(), 0, environment); environment = NULL;
	if (!created) {
		dropbear_win_logf("Remote process startup failed: Windows error %lu\r\n", (unsigned long)GetLastError());
		goto fail;
	}
	if (!AssignProcessToJobObject(job, process.hProcess)) {
		dropbear_win_logf("Task Job assignment failed: Windows error %lu\r\n", (unsigned long)GetLastError());
		CloseHandle(process.hThread);
		goto fail_process;
	}
	if (ResumeThread(process.hThread) == (DWORD)-1) {
		CloseHandle(process.hThread);
		goto fail_process;
	}
	CloseHandle(process.hThread);
	CloseHandle(stdin_read); stdin_read = NULL;
	CloseHandle(stdout_write); stdout_write = NULL;
	CloseHandle(stderr_write); stderr_write = NULL;

	if (dropbear_win_socketpair(input_sockets) ||
		dropbear_win_socketpair(output_sockets) ||
		dropbear_win_socketpair(error_sockets)) goto fail_process;
	transcode_terminal = !internal_mode && !powershell &&
		(!command || !command[0] || (terminal && terminal[0]));
	shell_codepage = GetOEMCP();
	if (!internal_mode && (!command || !command[0]) &&
			!write_session_motd(output_sockets[1], shell, ssh_user, terminal, connection))
		goto fail_process;
	if (start_bridge(input_sockets[1], stdin_write, 1,
			transcode_terminal ? CP_UTF8 : 0,
			transcode_terminal ? shell_codepage : 0)) goto fail_process;
	stdin_write = NULL; input_sockets[1] = -1;
	if (start_bridge(output_sockets[1], stdout_read, 0,
			transcode_terminal ? shell_codepage : 0,
			transcode_terminal ? CP_UTF8 : 0)) goto fail_process;
	stdout_read = NULL; output_sockets[1] = -1;
	if (start_bridge(error_sockets[1], stderr_read, 0,
			transcode_terminal ? shell_codepage : 0,
			transcode_terminal ? CP_UTF8 : 0)) goto fail_process;
	stderr_read = NULL; error_sockets[1] = -1;
	if (register_process(process.hProcess, process.dwProcessId, job) != 0) goto fail_process;
	*writefd = input_sockets[0];
	*readfd = output_sockets[0];
	if (errfd) *errfd = error_sockets[0];
	else dropbear_win_close(error_sockets[0]);
	*pid = (pid_t)process.dwProcessId;
	HeapFree(GetProcessHeap(), 0, wide_command);
	HeapFree(GetProcessHeap(), 0, command_line);
	return 0;

fail_process:
	TerminateProcess(process.hProcess, 1);
	CloseHandle(process.hProcess);
fail:
	if (job) CloseHandle(job);
	{
		int i;
		for (i = 0; i < 2; i++) {
			if (input_sockets[i] >= 0) dropbear_win_close(input_sockets[i]);
			if (output_sockets[i] >= 0) dropbear_win_close(output_sockets[i]);
			if (error_sockets[i] >= 0) dropbear_win_close(error_sockets[i]);
		}
	}
	if (environment) HeapFree(GetProcessHeap(), 0, environment);
	if (stdin_read) CloseHandle(stdin_read);
	if (stdin_write) CloseHandle(stdin_write);
	if (stdout_read) CloseHandle(stdout_read);
	if (stdout_write) CloseHandle(stdout_write);
	if (stderr_read) CloseHandle(stderr_read);
	if (stderr_write) CloseHandle(stderr_write);
	if (wide_command) HeapFree(GetProcessHeap(), 0, wide_command);
	if (command_line) HeapFree(GetProcessHeap(), 0, command_line);
	return -1;
}

struct connection_payload {
	WSAPROTOCOL_INFOW socket_info;
	WSAPROTOCOL_INFOW auth_info;
	HANDLE parent_process;
	HANDLE log_mutex;
};

/* A connection watches an actual process handle, not a PID that can be reused.
 * ExitProcess closes the connection-owned Jobs, including after a hard kill of
 * the listener. The watcher never touches the SSH event-loop state. */
static unsigned __stdcall watch_listener(void *opaque) {
	HANDLE parent = opaque;
	WaitForSingleObject(parent, INFINITE);
	CloseHandle(parent);
	ExitProcess(0);
	return 0;
}

int dropbear_win_spawn_connection(int socket_fd, int auth_fd, int argc, char **argv) {
	SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
	STARTUPINFOW startup;
	PROCESS_INFORMATION process;
	struct connection_payload payload;
	HANDLE child_read = NULL, parent_write = NULL;
	HANDLE parent_process = NULL;
	wchar_t executable[MAX_PATH];
	wchar_t *command_line = NULL;
	wchar_t handle_text[32];
	size_t used = 0;
	int i;
	DWORD written = 0;
	BOOL created;

	memset(&startup, 0, sizeof(startup));
	memset(&process, 0, sizeof(process));
	startup.cb = sizeof(startup);
	if (!CreatePipe(&child_read, &parent_write, &security, 0)) return -1;
	SetHandleInformation(parent_write, HANDLE_FLAG_INHERIT, 0);
	if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
		&parent_process, SYNCHRONIZE, TRUE, 0)) goto fail;
	payload.parent_process = parent_process;
	payload.log_mutex = dropbear_win_log_handle();
	if (!payload.log_mutex) goto fail;
	if (!GetModuleFileNameW(NULL, executable, MAX_PATH)) goto fail;
	command_line = calloc(32768, sizeof(*command_line));
	_snwprintf(handle_text, 32, L"%llu", (unsigned long long)(uintptr_t)child_read);
	if (!command_line || !exec_argument(command_line, &used, executable) ||
		!exec_argument(command_line, &used, L"--dropbear-win-child") ||
		!exec_argument(command_line, &used, handle_text)) goto fail;
	for (i = 1; i < argc; i++) {
		wchar_t *argument = utf8_to_wide(argv[i]);
		int ok = argument && exec_argument(command_line, &used, argument);
		if (argument) HeapFree(GetProcessHeap(), 0, argument);
		if (!ok) goto fail;
	}
	created = CreateProcessW(executable, command_line, NULL, NULL, TRUE,
		CREATE_SUSPENDED, NULL, NULL, &startup, &process);
	if (!created) goto fail;
	if (dropbear_win_export_socket(socket_fd, process.dwProcessId, &payload.socket_info) != 0 ||
		dropbear_win_export_socket(auth_fd, process.dwProcessId, &payload.auth_info) != 0 ||
		!WriteFile(parent_write, &payload, sizeof(payload), &written, NULL) ||
		written != sizeof(payload) || ResumeThread(process.hThread) == (DWORD)-1 ||
		register_process(process.hProcess, process.dwProcessId, NULL) != 0) {
		TerminateProcess(process.hProcess, 1);
		CloseHandle(process.hThread);
		CloseHandle(process.hProcess);
		goto fail;
	}
	CloseHandle(process.hThread);
	CloseHandle(child_read);
	CloseHandle(parent_write);
	CloseHandle(parent_process);
	free(command_line);
	return 0;

fail:
	if (child_read) CloseHandle(child_read);
	if (parent_write) CloseHandle(parent_write);
	if (parent_process) CloseHandle(parent_process);
	free(command_line);
	return -1;
}

int dropbear_win_receive_connection(const char *pipe_handle_text, int *auth_fd) {
	struct connection_payload payload;
	HANDLE pipe_handle;
	DWORD count = 0;
	unsigned long long value;
	char *end = NULL;
	int socket_fd;
	uintptr_t watcher;
	value = _strtoui64(pipe_handle_text, &end, 10);
	if (!end || *end != '\0') return -1;
	pipe_handle = (HANDLE)(uintptr_t)value;
	if (!ReadFile(pipe_handle, &payload, sizeof(payload), &count, NULL) ||
		count != sizeof(payload)) {
		CloseHandle(pipe_handle);
		return -1;
	}
	CloseHandle(pipe_handle);
	dropbear_win_log_adopt(payload.log_mutex);
	SetHandleInformation(payload.parent_process, HANDLE_FLAG_INHERIT, 0);
	watcher = _beginthreadex(NULL, 0, watch_listener, payload.parent_process, 0, NULL);
	if (!watcher) { CloseHandle(payload.parent_process); return -1; }
	CloseHandle((HANDLE)watcher);
	socket_fd = dropbear_win_import_socket(&payload.socket_info);
	*auth_fd = dropbear_win_import_socket(&payload.auth_info);
	if (socket_fd < 0 || *auth_fd < 0) {
		if (socket_fd >= 0) dropbear_win_close(socket_fd);
		if (*auth_fd >= 0) dropbear_win_close(*auth_fd);
		return -1;
	}
	return socket_fd;
}

pid_t dropbear_win_waitpid(pid_t requested_pid, int *status, int options) {
	unsigned int i;
	(void)options;
	ensure_process_table();
	EnterCriticalSection(&process_lock);
	for (i = 0; i < sizeof(processes) / sizeof(processes[0]); i++) {
		DWORD exit_code;
		if (!processes[i].process ||
			(requested_pid > 0 && processes[i].pid != (DWORD)requested_pid)) continue;
		if (WaitForSingleObject(processes[i].process, 0) != WAIT_OBJECT_0) continue;
		GetExitCodeProcess(processes[i].process, &exit_code);
		/* Join the callback before closing the process or reusing its slot. */
		if (processes[i].exit_wait)
			UnregisterWaitEx(processes[i].exit_wait, INVALID_HANDLE_VALUE);
		/* Tasks are scoped to their channel: stop descendants when the direct
		 * command exits so inherited output handles cannot hold EOF forever. */
		if (processes[i].job) CloseHandle(processes[i].job);
		CloseHandle(processes[i].process);
		requested_pid = (pid_t)processes[i].pid;
		memset(&processes[i], 0, sizeof(processes[i]));
		LeaveCriticalSection(&process_lock);
		if (status) *status = (int)exit_code;
		return requested_pid;
	}
	LeaveCriticalSection(&process_lock);
	return 0;
}

int dropbear_win_kill(pid_t pid, int signal_number) {
	unsigned int i;
	(void)signal_number;
	ensure_process_table();
	EnterCriticalSection(&process_lock);
	for (i = 0; i < sizeof(processes) / sizeof(processes[0]); i++) {
		if (processes[i].process && processes[i].pid == (DWORD)pid) {
			BOOL result = processes[i].job ? TerminateJobObject(processes[i].job, 1)
				: TerminateProcess(processes[i].process, 1);
			/* Keep the handle until waitpid delivers the exit status. */
			LeaveCriticalSection(&process_lock);
			return result ? 0 : -1;
		}
	}
	LeaveCriticalSection(&process_lock);
	return -1;
}

void dropbear_win_reap_connections(void) {
	int status;
	while (dropbear_win_waitpid(-1, &status, WNOHANG) > 0) { }
}

void dropbear_win_process_cleanup(void) {
	unsigned int i;
	ensure_process_table();
	EnterCriticalSection(&process_lock);
	for (i = 0; i < sizeof(processes) / sizeof(processes[0]); i++) {
		if (!processes[i].process) continue;
		if (processes[i].exit_wait)
			UnregisterWaitEx(processes[i].exit_wait, INVALID_HANDLE_VALUE);
		if (processes[i].job) CloseHandle(processes[i].job);
		else TerminateProcess(processes[i].process, 1);
		WaitForSingleObject(processes[i].process, 3000);
		CloseHandle(processes[i].process);
		memset(&processes[i], 0, sizeof(processes[i]));
	}
	LeaveCriticalSection(&process_lock);
}
