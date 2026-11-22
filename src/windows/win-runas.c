/* Built-in Windows user-switching command (`su` / `runas-user`) for Dropbear-win.
 * Allows SSH commands under the LocalSystem service to run synchronously as a
 * logged-on Windows user with that user's primary token, environment, profile,
 * HKCU hive, and Windows Credential Manager, streaming stdout/stderr/exit code. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include <wtsapi32.h>

static HMODULE runas_load_system_dll(const wchar_t *name) {
	wchar_t path[MAX_PATH];
	DWORD len = GetSystemDirectoryW(path, MAX_PATH);
	if (!len || len >= MAX_PATH || len + 1 + wcslen(name) >= MAX_PATH) return NULL;
	path[len++] = L'\\';
	wcscpy(path + len, name);
	return LoadLibraryW(path);
}

static void runas_enable_privileges(void) {
	static const wchar_t *const names[] = {
		L"SeTcbPrivilege",
		L"SeAssignPrimaryTokenPrivilege",
		L"SeIncreaseQuotaPrivilege"
	};
	HANDLE token = NULL;
	size_t i;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		return;
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		TOKEN_PRIVILEGES tp;
		LUID luid;
		if (LookupPrivilegeValueW(NULL, names[i], &luid)) {
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
		}
	}
	CloseHandle(token);
}

static const char *wts_state_name(WTS_CONNECTSTATE_CLASS state) {
	switch (state) {
		case WTSActive: return "active";
		case WTSConnected: return "connected";
		case WTSDisconnected: return "disconnected";
		case WTSIdle: return "idle";
		case WTSListen: return "listen";
		default: return "other";
	}
}

static void runas_json_escape(FILE *stream, const char *s) {
	fputc('"', stream);
	for (; s && *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\') { fputc('\\', stream); fputc(c, stream); }
		else if (c == '\n') fputs("\\n", stream);
		else if (c == '\r') fputs("\\r", stream);
		else if (c == '\t') fputs("\\t", stream);
		else if (c < 0x20) fprintf(stream, "\\u%04x", c);
		else fputc(c, stream);
	}
	fputc('"', stream);
}

static void runas_print_usage(FILE *stream) {
	fputs(
		"Usage:\n"
		"  su --list                          List logged-on Windows user sessions (JSON)\n"
		"  su <username> <command...>         Run command as logged-on Windows user\n"
		"  su --active <command...>           Run command as the active logged-on user\n"
		"  su --session <id> <command...>     Run command in a specific WTS session ID\n"
		"Alias: runas-user\n",
		stream);
}

static int runas_list_sessions(void) {
	typedef BOOL (WINAPI *enum_sessions_fn)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW *, DWORD *);
	typedef BOOL (WINAPI *query_session_fn)(HANDLE, DWORD, WTS_INFO_CLASS, LPWSTR *, DWORD *);
	typedef void (WINAPI *wts_free_fn)(PVOID);
	HMODULE wts = runas_load_system_dll(L"wtsapi32.dll");
	enum_sessions_fn enum_sessions;
	query_session_fn query_session;
	wts_free_fn wts_free;
	PWTS_SESSION_INFOW sessions = NULL;
	DWORD count = 0, i;
	int first = 1;

	if (!wts) {
		fputs("su: wtsapi32.dll unavailable\n", stderr);
		return 1;
	}
	enum_sessions = (enum_sessions_fn)(void *)GetProcAddress(wts, "WTSEnumerateSessionsW");
	query_session = (query_session_fn)(void *)GetProcAddress(wts, "WTSQuerySessionInformationW");
	wts_free = (wts_free_fn)(void *)GetProcAddress(wts, "WTSFreeMemory");
	if (!enum_sessions || !query_session || !wts_free) {
		FreeLibrary(wts);
		fputs("su: WTS session APIs unavailable\n", stderr);
		return 1;
	}
	if (!enum_sessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
		fprintf(stderr, "su: WTSEnumerateSessionsW failed: error %lu\n", (unsigned long)GetLastError());
		FreeLibrary(wts);
		return 1;
	}
	fputc('[', stdout);
	for (i = 0; i < count; i++) {
		LPWSTR user_w = NULL, dom_w = NULL;
		DWORD user_bytes = 0, dom_bytes = 0;
		char user_u8[512] = "", dom_u8[512] = "";
		if (sessions[i].SessionId == 0) continue;
		if (!query_session(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId, WTSUserName, &user_w, &user_bytes))
			continue;
		if (!user_w || !user_w[0]) {
			if (user_w) wts_free(user_w);
			continue;
		}
		WideCharToMultiByte(CP_UTF8, 0, user_w, -1, user_u8, sizeof(user_u8), NULL, NULL);
		wts_free(user_w);
		if (query_session(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId, WTSDomainName, &dom_w, &dom_bytes) && dom_w) {
			WideCharToMultiByte(CP_UTF8, 0, dom_w, -1, dom_u8, sizeof(dom_u8), NULL, NULL);
			wts_free(dom_w);
		}
		if (!first) fputc(',', stdout);
		fprintf(stdout, "{\"session_id\":%lu,\"domain\":", (unsigned long)sessions[i].SessionId);
		runas_json_escape(stdout, dom_u8);
		fputs(",\"username\":", stdout);
		runas_json_escape(stdout, user_u8);
		fputs(",\"state\":", stdout);
		runas_json_escape(stdout, wts_state_name(sessions[i].State));
		fputc('}', stdout);
		first = 0;
	}
	fputs("]\n", stdout);
	wts_free(sessions);
	FreeLibrary(wts);
	return 0;
}

static wchar_t *runas_utf8_to_wide(const char *s) {
	int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
	wchar_t *w;
	if (n <= 0) return NULL;
	w = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)n * sizeof(*w));
	if (!w) return NULL;
	if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n)) {
		HeapFree(GetProcessHeap(), 0, w);
		return NULL;
	}
	return w;
}

static int runas_execute(int mode_active, DWORD requested_session,
		const char *target_user, const char *command_utf8) {
	typedef DWORD (WINAPI *active_session_fn)(void);
	typedef BOOL (WINAPI *enum_sessions_fn)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW *, DWORD *);
	typedef BOOL (WINAPI *query_session_fn)(HANDLE, DWORD, WTS_INFO_CLASS, LPWSTR *, DWORD *);
	typedef BOOL (WINAPI *query_user_token_fn)(ULONG, PHANDLE);
	typedef void (WINAPI *wts_free_fn)(PVOID);
	typedef BOOL (WINAPI *create_env_fn)(LPVOID *, HANDLE, BOOL);
	typedef BOOL (WINAPI *destroy_env_fn)(LPVOID);
	HMODULE kernel, wts = NULL, userenv = NULL;
	active_session_fn active_session;
	enum_sessions_fn enum_sessions;
	query_session_fn query_session;
	query_user_token_fn query_user_token;
	wts_free_fn wts_free;
	create_env_fn create_env;
	destroy_env_fn destroy_env;
	DWORD chosen_session = 0xffffffffUL;
	HANDLE user_token = NULL, primary_token = NULL;
	LPVOID env_block = NULL;
	wchar_t *wide_cmd = NULL, *wide_target = NULL, *cmd_line = NULL;
	wchar_t sys_dir[MAX_PATH], shell[MAX_PATH];
	const wchar_t *user_profile = NULL;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD exit_code = 1;
	int status = 1;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	runas_enable_privileges();

	kernel = GetModuleHandleW(L"kernel32.dll");
	wts = runas_load_system_dll(L"wtsapi32.dll");
	userenv = runas_load_system_dll(L"userenv.dll");
	if (!wts || !userenv) {
		fputs("su: requires Windows Vista/Server 2008 or newer (wtsapi32/userenv)\n", stderr);
		goto done;
	}
	active_session = kernel ? (active_session_fn)(void *)GetProcAddress(kernel, "WTSGetActiveConsoleSessionId") : NULL;
	enum_sessions = (enum_sessions_fn)(void *)GetProcAddress(wts, "WTSEnumerateSessionsW");
	query_session = (query_session_fn)(void *)GetProcAddress(wts, "WTSQuerySessionInformationW");
	query_user_token = (query_user_token_fn)(void *)GetProcAddress(wts, "WTSQueryUserToken");
	wts_free = (wts_free_fn)(void *)GetProcAddress(wts, "WTSFreeMemory");
	create_env = (create_env_fn)(void *)GetProcAddress(userenv, "CreateEnvironmentBlock");
	destroy_env = (destroy_env_fn)(void *)GetProcAddress(userenv, "DestroyEnvironmentBlock");
	if (!enum_sessions || !query_session || !query_user_token || !wts_free || !create_env || !destroy_env) {
		fputs("su: required WTS/UserEnv APIs unavailable\n", stderr);
		goto done;
	}

	if (requested_session != 0xffffffffUL) {
		chosen_session = requested_session;
	} else if (mode_active) {
		PWTS_SESSION_INFOW sessions = NULL;
		DWORD count = 0, i;
		if (active_session) {
			DWORD sid = active_session();
			if (sid != 0 && sid != 0xffffffffUL) {
				LPWSTR uw = NULL; DWORD ub = 0;
				if (query_session(WTS_CURRENT_SERVER_HANDLE, sid, WTSUserName, &uw, &ub) && uw && uw[0]) {
					chosen_session = sid;
				}
				if (uw) wts_free(uw);
			}
		}
		if (chosen_session == 0xffffffffUL &&
				enum_sessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count) && sessions) {
			for (i = 0; i < count && chosen_session == 0xffffffffUL; i++) {
				LPWSTR uw = NULL; DWORD ub = 0;
				if (sessions[i].SessionId == 0) continue;
				if (sessions[i].State != WTSActive && sessions[i].State != WTSConnected) continue;
				if (query_session(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId, WTSUserName, &uw, &ub) && uw && uw[0])
					chosen_session = sessions[i].SessionId;
				if (uw) wts_free(uw);
			}
			for (i = 0; i < count && chosen_session == 0xffffffffUL; i++) {
				LPWSTR uw = NULL; DWORD ub = 0;
				if (sessions[i].SessionId == 0) continue;
				if (sessions[i].State != WTSDisconnected) continue;
				if (query_session(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId, WTSUserName, &uw, &ub) && uw && uw[0])
					chosen_session = sessions[i].SessionId;
				if (uw) wts_free(uw);
			}
			wts_free(sessions);
		}
		if (chosen_session == 0xffffffffUL) {
			fputs("su: no logged-on user session found (run `su --list`)\n", stderr);
			goto done;
		}
	} else {
		PWTS_SESSION_INFOW sessions = NULL;
		DWORD count = 0, i;
		DWORD fallback_session = 0xffffffffUL;
		wide_target = runas_utf8_to_wide(target_user);
		if (!wide_target) goto done;
		if (!enum_sessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count) || !sessions) {
			fprintf(stderr, "su: WTSEnumerateSessionsW failed: error %lu\n", (unsigned long)GetLastError());
			goto done;
		}
		for (i = 0; i < count; i++) {
			LPWSTR uw = NULL, dw = NULL;
			DWORD ub = 0, db = 0;
			wchar_t full[520];
			int match = 0;
			if (sessions[i].SessionId == 0) continue;
			if (!query_session(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId, WTSUserName, &uw, &ub) || !uw || !uw[0]) {
				if (uw) wts_free(uw);
				continue;
			}
			if (query_session(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId, WTSDomainName, &dw, &db) && dw && dw[0]) {
				_snwprintf(full, 520, L"%ls\\%ls", dw, uw);
			} else {
				_snwprintf(full, 520, L"%ls", uw);
			}
			if (_wcsicmp(uw, wide_target) == 0 || _wcsicmp(full, wide_target) == 0) match = 1;
			wts_free(uw);
			if (dw) wts_free(dw);
			if (match) {
				if (sessions[i].State == WTSActive || sessions[i].State == WTSConnected) {
					chosen_session = sessions[i].SessionId;
					break;
				}
				if (fallback_session == 0xffffffffUL) fallback_session = sessions[i].SessionId;
			}
		}
		wts_free(sessions);
		if (chosen_session == 0xffffffffUL) chosen_session = fallback_session;
		if (chosen_session == 0xffffffffUL) {
			fprintf(stderr, "su: no logged-on session found for user '%s' (run `su --list`)\n", target_user);
			goto done;
		}
	}

	if (!query_user_token(chosen_session, &user_token)) {
		DWORD err = GetLastError();
		fprintf(stderr, "su: WTSQueryUserToken(session %lu) failed: error %lu (requires LocalSystem service)\n",
			(unsigned long)chosen_session, (unsigned long)err);
		goto done;
	}
	if (!DuplicateTokenEx(user_token, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &primary_token)) {
		fprintf(stderr, "su: DuplicateTokenEx failed: error %lu\n", (unsigned long)GetLastError());
		goto done;
	}
	if (!create_env(&env_block, primary_token, FALSE)) {
		fprintf(stderr, "su: CreateEnvironmentBlock failed: error %lu\n", (unsigned long)GetLastError());
		goto done;
	}
	/* Locate USERPROFILE from the user's environment block for default cwd. */
	{
		const wchar_t *p;
		for (p = (const wchar_t *)env_block; *p; p += wcslen(p) + 1) {
			if (_wcsnicmp(p, L"USERPROFILE=", 12) == 0) {
				user_profile = p + 12;
				break;
			}
		}
	}

	if (!GetSystemDirectoryW(sys_dir, MAX_PATH)) goto done;
	_snwprintf(shell, MAX_PATH, L"%ls\\cmd.exe", sys_dir);
	wide_cmd = runas_utf8_to_wide(command_utf8);
	if (!wide_cmd) goto done;
	{
		size_t cap = wcslen(shell) + wcslen(wide_cmd) + 32;
		if (cap >= 32767) {
			fputs("su: command exceeds Windows command-line limit\n", stderr);
			goto done;
		}
		cmd_line = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap * sizeof(*cmd_line));
		if (!cmd_line) goto done;
		_snwprintf(cmd_line, cap, L"\"%ls\" /d /s /c \"%ls\"", shell, wide_cmd);
	}

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

	if (!CreateProcessAsUserW(primary_token, shell, cmd_line, NULL, NULL, TRUE,
			CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
			env_block, user_profile, &si, &pi)) {
		fprintf(stderr, "su: CreateProcessAsUserW failed: error %lu\n", (unsigned long)GetLastError());
		goto done;
	}
	CloseHandle(pi.hThread);
	WaitForSingleObject(pi.hProcess, INFINITE);
	if (GetExitCodeProcess(pi.hProcess, &exit_code)) status = (int)exit_code;
	CloseHandle(pi.hProcess);

done:
	if (cmd_line) HeapFree(GetProcessHeap(), 0, cmd_line);
	if (wide_cmd) HeapFree(GetProcessHeap(), 0, wide_cmd);
	if (wide_target) HeapFree(GetProcessHeap(), 0, wide_target);
	if (env_block && destroy_env) destroy_env(env_block);
	if (primary_token) CloseHandle(primary_token);
	if (user_token) CloseHandle(user_token);
	if (userenv) FreeLibrary(userenv);
	if (wts) FreeLibrary(wts);
	return status;
}

int dropbear_win_is_su_command(const char *command) {
	const char *p;
	if (!command || strlen(command) > 15000) return 0;
	p = command;
	while (*p == ' ' || *p == '\t') p++;
	if (strncmp(p, "su", 2) == 0 && (p[2] == '\0' || p[2] == ' ' || p[2] == '\t')) return 1;
	if (strncmp(p, "runas-user", 10) == 0 && (p[10] == '\0' || p[10] == ' ' || p[10] == '\t')) return 1;
	return 0;
}

int dropbear_win_su_exec_command(const char *command) {
	const char *p = command;
	char tok[256];
	size_t tlen = 0;

	while (*p == ' ' || *p == '\t') p++;
	if (strncmp(p, "runas-user", 10) == 0) p += 10;
	else if (strncmp(p, "su", 2) == 0) p += 2;
	while (*p == ' ' || *p == '\t') p++;
	if (!*p || !strcmp(p, "-h") || !strcmp(p, "--help")) {
		runas_print_usage(stdout);
		return 0;
	}
	if (!strcmp(p, "--list") || !strcmp(p, "-l")) {
		return runas_list_sessions();
	}

	/* Parse first argument: --active, --session <id>, or <username> (possibly quoted). */
	if (*p == '"' || *p == '\'') {
		char q = *p++;
		while (*p && *p != q) {
			if (tlen + 1 < sizeof(tok)) tok[tlen++] = *p;
			p++;
		}
		if (*p == q) p++;
	} else {
		while (*p && *p != ' ' && *p != '\t') {
			if (tlen + 1 < sizeof(tok)) tok[tlen++] = *p;
			p++;
		}
	}
	tok[tlen] = '\0';
	while (*p == ' ' || *p == '\t') p++;

	if (!strcmp(tok, "--active")) {
		if (!*p) { runas_print_usage(stderr); return 2; }
		return runas_execute(1, 0xffffffffUL, NULL, p);
	}
	if (!strcmp(tok, "--session")) {
		char *end = NULL;
		unsigned long sid;
		if (!*p) { runas_print_usage(stderr); return 2; }
		sid = strtoul(p, &end, 10);
		if (!end || end == p || (*end != ' ' && *end != '\t')) {
			fputs("su: --session requires a numeric session ID followed by a command\n", stderr);
			return 2;
		}
		p = end;
		while (*p == ' ' || *p == '\t') p++;
		if (!*p) { runas_print_usage(stderr); return 2; }
		return runas_execute(0, (DWORD)sid, NULL, p);
	}
	if (!tok[0] || !*p) {
		runas_print_usage(stderr);
		return 2;
	}
	return runas_execute(0, 0xffffffffUL, tok, p);
}
#endif
