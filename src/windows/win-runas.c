/* Built-in Windows user-switching command (`su` / `runas-user`) for Dropbear-win.
 * Supports:
 *   - Running as a logged-on Windows user via WTSQueryUserToken (with optional --admin UAC elevation via TokenLinkedToken)
 *   - Force-logging on a non-logged-in local user or Administrator via LogonUserW + LoadUserProfileW (-p / --password)
 */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include <wtsapi32.h>

typedef struct _DB_PROFILEINFOW {
	DWORD dwSize;
	DWORD dwFlags;
	LPWSTR lpUserName;
	LPWSTR lpProfilePath;
	LPWSTR lpDefaultPath;
	LPWSTR lpServerName;
	LPWSTR lpPolicyPath;
	HANDLE hProfile;
} DB_PROFILEINFOW;

#ifndef DB_TOKEN_LINKED_TOKEN
#define DB_TOKEN_LINKED_TOKEN ((TOKEN_INFORMATION_CLASS)19)
#endif
#ifndef DB_TOKEN_ELEVATION_TYPE
#define DB_TOKEN_ELEVATION_TYPE ((TOKEN_INFORMATION_CLASS)18)
#endif

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
		L"SeIncreaseQuotaPrivilege",
		L"SeBackupPrivilege",
		L"SeRestorePrivilege"
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
		"  su --list                                                      List logged-on Windows user sessions (JSON)\n"
		"  su [--admin] [--in-session] [--detach] [--log <f>] <user> <c>  Run silently as logged-on user\n"
		"  su [--admin] [--in-session] [--detach] [--log <f>] --active <c> Run silently as active logged-on user\n"
		"  su [--admin] [--detach] [--log <f>] --session <id> <c>         Run silently inside specific WTS session ID\n"
		"  su [--admin] [--detach] [--log <f>] -p <pwd> <user> <c>        Force-logon local user/Administrator\n"
		"  bg [--log <f>] [--active|--user <u|id>|--admin|--in-session] <cmd...>  Launch detached silent background process (survives SSH disconnect)\n"
		"Aliases: runas-user, --elevated (same as --admin), --password (same as -p)\n",
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

/* If the token is a UAC-limited split token, obtain its linked elevated
 * Administrator primary token (High integrity). */
static void try_elevate_linked_token(HANDLE *token_ptr) {
	DWORD elev_type = 0, ret = 0;
	HANDLE linked = NULL, dup = NULL;
	if (!token_ptr || !*token_ptr) return;
	if (!GetTokenInformation(*token_ptr, DB_TOKEN_ELEVATION_TYPE, &elev_type, sizeof(elev_type), &ret))
		return;
	/* TokenElevationTypeLimited == 3 */
	if (elev_type != 3) return;
	if (!GetTokenInformation(*token_ptr, DB_TOKEN_LINKED_TOKEN, &linked, sizeof(linked), &ret) || !linked)
		return;
	/* Linked token may be impersonation or primary; duplicate as Primary. */
	if (DuplicateTokenEx(linked, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dup)) {
		CloseHandle(linked);
		CloseHandle(*token_ptr);
		*token_ptr = dup;
	} else {
		/* If already primary, use directly. */
		CloseHandle(*token_ptr);
		*token_ptr = linked;
	}
}


/* Append non-interactive defaults so background tools (git/GCM/ssh) never hang
 * or attempt to show GUI prompts. Returns a HeapAlloc block; caller frees it. */
static wchar_t *runas_augment_silent_env(const wchar_t *base_env) {
	static const wchar_t *const extras[] = {
		L"GIT_TERMINAL_PROMPT=0",
		L"GCM_INTERACTIVE=never",
		L"SSH_ASKPASS_REQUIRE=never"
	};
	const wchar_t *p;
	size_t total = 2, i;
	wchar_t *buf, *out;

	for (p = base_env; *p; p += wcslen(p) + 1) total += wcslen(p) + 1;
	for (i = 0; i < sizeof(extras) / sizeof(extras[0]); i++) total += wcslen(extras[i]) + 1;
	buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total * sizeof(*buf));
	if (!buf) return NULL;
	out = buf;
	for (p = base_env; *p; p += wcslen(p) + 1) {
		if (!_wcsnicmp(p, L"GIT_TERMINAL_PROMPT=", 20) ||
			!_wcsnicmp(p, L"GCM_INTERACTIVE=", 16) ||
			!_wcsnicmp(p, L"SSH_ASKPASS_REQUIRE=", 20)) continue;
		wcscpy(out, p);
		out += wcslen(out) + 1;
	}
	for (i = 0; i < sizeof(extras) / sizeof(extras[0]); i++) {
		wcscpy(out, extras[i]);
		out += wcslen(out) + 1;
	}
	return buf;
}


static int open_detached_stdio(const char *log_utf8, HANDLE *nul_out, HANDLE *log_out) {
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
	*nul_out = INVALID_HANDLE_VALUE;
	*log_out = INVALID_HANDLE_VALUE;
	*nul_out = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
	if (*nul_out == INVALID_HANDLE_VALUE) return 0;
	if (log_utf8 && log_utf8[0]) {
		wchar_t *wide_log = runas_utf8_to_wide(log_utf8);
		if (!wide_log) { CloseHandle(*nul_out); *nul_out = INVALID_HANDLE_VALUE; return 0; }
		*log_out = CreateFileW(wide_log, GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		HeapFree(GetProcessHeap(), 0, wide_log);
		if (*log_out == INVALID_HANDLE_VALUE) {
			CloseHandle(*nul_out);
			*nul_out = INVALID_HANDLE_VALUE;
			return 0;
		}
		SetFilePointer(*log_out, 0, NULL, FILE_END);
	}
	return 1;
}

static int runas_bg_current_identity(const char *log_utf8, const char *command_utf8) {
	wchar_t sys_dir[MAX_PATH], shell[MAX_PATH];
	wchar_t *wide_cmd = NULL, *cmd_line = NULL;
	wchar_t *inherited = GetEnvironmentStringsW();
	wchar_t *silent_env = NULL;
	HANDLE nul_h = INVALID_HANDLE_VALUE, log_h = INVALID_HANDLE_VALUE;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	int status = 1;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	if (!GetSystemDirectoryW(sys_dir, MAX_PATH)) goto done;
	_snwprintf(shell, MAX_PATH, L"%ls\\cmd.exe", sys_dir);
	wide_cmd = runas_utf8_to_wide(command_utf8);
	if (!wide_cmd) goto done;
	{
		size_t cap = wcslen(shell) + wcslen(wide_cmd) + 32;
		if (cap >= 32767) {
			fputs("bg: command exceeds Windows command-line limit\n", stderr);
			goto done;
		}
		cmd_line = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap * sizeof(*cmd_line));
		if (!cmd_line) goto done;
		_snwprintf(cmd_line, cap, L"\"%ls\" /d /s /c \"%ls\"", shell, wide_cmd);
	}
	if (!open_detached_stdio(log_utf8, &nul_h, &log_h)) {
		fprintf(stderr, "bg: failed to open detached stdio/log: error %lu\n", (unsigned long)GetLastError());
		goto done;
	}
	if (inherited) silent_env = runas_augment_silent_env(inherited);
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW | STARTF_FORCEOFFFEEDBACK;
	si.wShowWindow = SW_HIDE;
	si.hStdInput = nul_h;
	si.hStdOutput = (log_h != INVALID_HANDLE_VALUE) ? log_h : nul_h;
	si.hStdError = (log_h != INVALID_HANDLE_VALUE) ? log_h : nul_h;

	if (!CreateProcessW(shell, cmd_line, NULL, NULL, TRUE,
			CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
			silent_env, NULL, &si, &pi) &&
		!CreateProcessW(shell, cmd_line, NULL, NULL, TRUE,
			CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
			silent_env, NULL, &si, &pi)) {
		fprintf(stderr, "bg: CreateProcessW failed: error %lu\n", (unsigned long)GetLastError());
		goto done;
	}
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	fprintf(stdout, "{\"detached\":true,\"pid\":%lu,\"log\":", (unsigned long)pi.dwProcessId);
	if (log_utf8 && log_utf8[0]) runas_json_escape(stdout, log_utf8);
	else fputs("null", stdout);
	fputs("}\n", stdout);
	status = 0;

done:
	if (log_h != INVALID_HANDLE_VALUE) CloseHandle(log_h);
	if (nul_h != INVALID_HANDLE_VALUE) CloseHandle(nul_h);
	if (silent_env) HeapFree(GetProcessHeap(), 0, silent_env);
	if (inherited) FreeEnvironmentStringsW(inherited);
	if (cmd_line) HeapFree(GetProcessHeap(), 0, cmd_line);
	if (wide_cmd) HeapFree(GetProcessHeap(), 0, wide_cmd);
	return status;
}

static int runas_execute(int mode_active, int want_admin, int in_session, int detach,
		const char *log_utf8, DWORD requested_session,
		const char *target_user, const char *password_utf8, const char *command_utf8) {
	typedef DWORD (WINAPI *active_session_fn)(void);
	typedef BOOL (WINAPI *enum_sessions_fn)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW *, DWORD *);
	typedef BOOL (WINAPI *query_session_fn)(HANDLE, DWORD, WTS_INFO_CLASS, LPWSTR *, DWORD *);
	typedef BOOL (WINAPI *query_user_token_fn)(ULONG, PHANDLE);
	typedef void (WINAPI *wts_free_fn)(PVOID);
	typedef BOOL (WINAPI *create_env_fn)(LPVOID *, HANDLE, BOOL);
	typedef BOOL (WINAPI *destroy_env_fn)(LPVOID);
	typedef BOOL (WINAPI *load_profile_fn)(HANDLE, DB_PROFILEINFOW *);
	typedef BOOL (WINAPI *unload_profile_fn)(HANDLE, HANDLE);
	HMODULE kernel, wts = NULL, userenv = NULL;
	active_session_fn active_session;
	enum_sessions_fn enum_sessions;
	query_session_fn query_session;
	query_user_token_fn query_user_token;
	wts_free_fn wts_free;
	create_env_fn create_env;
	destroy_env_fn destroy_env;
	load_profile_fn load_profile;
	unload_profile_fn unload_profile;
	DWORD chosen_session = 0xffffffffUL;
	HANDLE primary_token = NULL;
	LPVOID env_block = NULL;
	wchar_t *silent_env = NULL;
	DB_PROFILEINFOW profile_info;
	int profile_loaded = 0;
	int use_wts_desktop = 1;
	wchar_t *wide_cmd = NULL, *wide_target = NULL, *wide_pass = NULL, *cmd_line = NULL;
	wchar_t sys_dir[MAX_PATH], shell[MAX_PATH];
	const wchar_t *user_profile = NULL;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD exit_code = 1;
	int status = 1;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	memset(&profile_info, 0, sizeof(profile_info));
	runas_enable_privileges();

	kernel = GetModuleHandleW(L"kernel32.dll");
	wts = runas_load_system_dll(L"wtsapi32.dll");
	userenv = runas_load_system_dll(L"userenv.dll");
	if (!userenv) {
		fputs("su: userenv.dll unavailable\n", stderr);
		goto done;
	}
	create_env = (create_env_fn)(void *)GetProcAddress(userenv, "CreateEnvironmentBlock");
	destroy_env = (destroy_env_fn)(void *)GetProcAddress(userenv, "DestroyEnvironmentBlock");
	load_profile = (load_profile_fn)(void *)GetProcAddress(userenv, "LoadUserProfileW");
	unload_profile = (unload_profile_fn)(void *)GetProcAddress(userenv, "UnloadUserProfile");
	if (!create_env || !destroy_env) {
		fputs("su: UserEnv APIs unavailable\n", stderr);
		goto done;
	}

	if (password_utf8 != NULL) {
		/* Force logon a local/domain user with credentials via LogonUserW + LoadUserProfileW. */
		wchar_t domain_buf[256] = L".";
		const wchar_t *user_part;
		wchar_t *slash;
		if (!target_user || !target_user[0]) {
			fputs("su: -p/--password requires a username\n", stderr);
			status = 2;
			goto done;
		}
		wide_target = runas_utf8_to_wide(target_user);
		wide_pass = runas_utf8_to_wide(password_utf8);
		if (!wide_target || !wide_pass) goto done;
		slash = wcschr(wide_target, L'\\');
		if (slash && (size_t)(slash - wide_target) < 255) {
			memcpy(domain_buf, wide_target, (size_t)(slash - wide_target) * sizeof(wchar_t));
			domain_buf[slash - wide_target] = L'\0';
			user_part = slash + 1;
		} else {
			user_part = wide_target;
		}
		if (!LogonUserW(user_part, domain_buf, wide_pass,
				LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &primary_token)) {
			fprintf(stderr, "su: LogonUserW('%s') failed: error %lu\n",
				target_user, (unsigned long)GetLastError());
			goto done;
		}
		use_wts_desktop = 0;
		if (want_admin) try_elevate_linked_token(&primary_token);
		if (load_profile && unload_profile) {
			profile_info.dwSize = sizeof(profile_info);
			profile_info.dwFlags = 1; /* PI_NOUI */
			profile_info.lpUserName = (LPWSTR)user_part;
			if (load_profile(primary_token, &profile_info)) profile_loaded = 1;
		}
	} else {
		if (!wts) {
			fputs("su: wtsapi32.dll unavailable\n", stderr);
			goto done;
		}
		active_session = kernel ? (active_session_fn)(void *)GetProcAddress(kernel, "WTSGetActiveConsoleSessionId") : NULL;
		enum_sessions = (enum_sessions_fn)(void *)GetProcAddress(wts, "WTSEnumerateSessionsW");
		query_session = (query_session_fn)(void *)GetProcAddress(wts, "WTSQuerySessionInformationW");
		query_user_token = (query_user_token_fn)(void *)GetProcAddress(wts, "WTSQueryUserToken");
		wts_free = (wts_free_fn)(void *)GetProcAddress(wts, "WTSFreeMemory");
		if (!enum_sessions || !query_session || !query_user_token || !wts_free) {
			fputs("su: required WTS APIs unavailable\n", stderr);
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
				fputs("su: no logged-on user session found (use `su -p <password> <user> <cmd>` to force-logon)\n", stderr);
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
				fprintf(stderr, "su: no logged-on session for '%s' (run `su --list` or use `su -p <password> %s <cmd>`)\n",
					target_user, target_user);
				goto done;
			}
		}

		if (!query_user_token(chosen_session, &primary_token)) {
			DWORD err = GetLastError();
			fprintf(stderr, "su: WTSQueryUserToken(session %lu) failed: error %lu (requires LocalSystem service)\n",
				(unsigned long)chosen_session, (unsigned long)err);
			goto done;
		}
		if (want_admin) try_elevate_linked_token(&primary_token);
	}

	if (!create_env(&env_block, primary_token, FALSE)) {
		fprintf(stderr, "su: CreateEnvironmentBlock failed: error %lu\n", (unsigned long)GetLastError());
		goto done;
	}
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

	silent_env = runas_augment_silent_env((const wchar_t *)env_block);
	/* Move a duplicate of the user's primary token into Session 0 so the command
	 * executes 100% silently in the background (physically isolated from the
	 * user's interactive desktop: zero window flash, zero focus steal, zero
	 * busy cursor) while keeping the user's SID, profile, HKCU, and credentials. */
	if (use_wts_desktop && !in_session) {
		HANDLE sess0_token = NULL;
		DWORD zero_session = 0;
		if (DuplicateTokenEx(primary_token, MAXIMUM_ALLOWED, NULL,
				SecurityImpersonation, TokenPrimary, &sess0_token)) {
			if (SetTokenInformation(sess0_token, TokenSessionId, &zero_session, sizeof(zero_session))) {
				CloseHandle(primary_token);
				primary_token = sess0_token;
				use_wts_desktop = 0;
			} else {
				CloseHandle(sess0_token);
			}
		}
	}

	{
		HANDLE nul_h = INVALID_HANDLE_VALUE, log_h = INVALID_HANDLE_VALUE;
		DWORD first_flags = detach
			? (CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT)
			: (CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT);
		DWORD second_flags = detach
			? (CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT)
			: (CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT);
		if (detach && !open_detached_stdio(log_utf8, &nul_h, &log_h)) {
			fprintf(stderr, "su: failed to open detached stdio/log: error %lu\n", (unsigned long)GetLastError());
			goto done;
		}
		si.cb = sizeof(si);
		if (use_wts_desktop) si.lpDesktop = L"winsta0\\default";
		si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW | STARTF_FORCEOFFFEEDBACK;
		si.wShowWindow = SW_HIDE;
		if (detach) {
			si.hStdInput = nul_h;
			si.hStdOutput = (log_h != INVALID_HANDLE_VALUE) ? log_h : nul_h;
			si.hStdError = (log_h != INVALID_HANDLE_VALUE) ? log_h : nul_h;
		} else {
			si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
			si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
			si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
		}

		if (!CreateProcessAsUserW(primary_token, shell, cmd_line, NULL, NULL, TRUE,
				first_flags, silent_env ? (LPVOID)silent_env : env_block, user_profile, &si, &pi) &&
			!CreateProcessAsUserW(primary_token, shell, cmd_line, NULL, NULL, TRUE,
				second_flags, silent_env ? (LPVOID)silent_env : env_block, user_profile, &si, &pi)) {
			if (log_h != INVALID_HANDLE_VALUE) CloseHandle(log_h);
			if (nul_h != INVALID_HANDLE_VALUE) CloseHandle(nul_h);
			fprintf(stderr, "su: CreateProcessAsUserW failed: error %lu\n", (unsigned long)GetLastError());
			goto done;
		}
		if (log_h != INVALID_HANDLE_VALUE) CloseHandle(log_h);
		if (nul_h != INVALID_HANDLE_VALUE) CloseHandle(nul_h);
		CloseHandle(pi.hThread);
		if (detach) {
			CloseHandle(pi.hProcess);
			fprintf(stdout, "{\"detached\":true,\"pid\":%lu,\"session_id\":%lu,\"log\":",
				(unsigned long)pi.dwProcessId,
				(unsigned long)(use_wts_desktop ? chosen_session : 0));
			if (log_utf8 && log_utf8[0]) runas_json_escape(stdout, log_utf8);
			else fputs("null", stdout);
			fputs("}\n", stdout);
			status = 0;
		} else {
			WaitForSingleObject(pi.hProcess, INFINITE);
			if (GetExitCodeProcess(pi.hProcess, &exit_code)) status = (int)exit_code;
			CloseHandle(pi.hProcess);
		}
	}

done:
	if (cmd_line) HeapFree(GetProcessHeap(), 0, cmd_line);
	if (wide_cmd) HeapFree(GetProcessHeap(), 0, wide_cmd);
	if (wide_target) HeapFree(GetProcessHeap(), 0, wide_target);
	if (wide_pass) {
		SecureZeroMemory(wide_pass, wcslen(wide_pass) * sizeof(wchar_t));
		HeapFree(GetProcessHeap(), 0, wide_pass);
	}
	if (silent_env) HeapFree(GetProcessHeap(), 0, silent_env);
	if (env_block && destroy_env) destroy_env(env_block);
	if (profile_loaded && unload_profile && primary_token && profile_info.hProfile)
		unload_profile(primary_token, profile_info.hProfile);
	if (primary_token) CloseHandle(primary_token);
	if (userenv) FreeLibrary(userenv);
	if (wts) FreeLibrary(wts);
	return status;
}

static const char *read_token(const char *p, char *out, size_t cap) {
	size_t n = 0;
	while (*p == ' ' || *p == '\t') p++;
	if (*p == '"' || *p == '\'') {
		char q = *p++;
		while (*p && *p != q) {
			if (n + 1 < cap) out[n++] = *p;
			p++;
		}
		if (*p == q) p++;
	} else {
		while (*p && *p != ' ' && *p != '\t') {
			if (n + 1 < cap) out[n++] = *p;
			p++;
		}
	}
	out[n] = '\0';
	while (*p == ' ' || *p == '\t') p++;
	return p;
}

int dropbear_win_is_su_command(const char *command) {
	const char *p;
	if (!command || strlen(command) > 15000) return 0;
	p = command;
	while (*p == ' ' || *p == '\t') p++;
	if (strncmp(p, "su", 2) == 0 && (p[2] == '\0' || p[2] == ' ' || p[2] == '\t')) return 1;
	if (strncmp(p, "bg", 2) == 0 && (p[2] == '\0' || p[2] == ' ' || p[2] == '\t')) return 1;
	if (strncmp(p, "runas-user", 10) == 0 && (p[10] == '\0' || p[10] == ' ' || p[10] == '\t')) return 1;
	return 0;
}

int dropbear_win_su_exec_command(const char *command) {
	const char *p = command;
	char tok[256];
	char user_buf[256] = "";
	char pass_buf[512] = "";
	char log_buf[1024] = "";
	int has_pass = 0;
	int want_admin = 0;
	int in_session = 0;
	int detach = 0;
	int is_bg = 0;
	int mode_active = 0;
	DWORD requested_session = 0xffffffffUL;

	while (*p == ' ' || *p == '\t') p++;
	if (strncmp(p, "runas-user", 10) == 0) p += 10;
	else if (strncmp(p, "bg", 2) == 0) { p += 2; is_bg = 1; detach = 1; }
	else if (strncmp(p, "su", 2) == 0) p += 2;
	while (*p == ' ' || *p == '\t') p++;
	if (!*p || !strcmp(p, "-h") || !strcmp(p, "--help")) {
		runas_print_usage(stdout);
		return 0;
	}
	if (!is_bg && (!strcmp(p, "--list") || !strcmp(p, "-l"))) {
		return runas_list_sessions();
	}

	while (*p) {
		const char *next = read_token(p, tok, sizeof(tok));
		if (!strcmp(tok, "--admin") || !strcmp(tok, "--elevated")) {
			want_admin = 1;
			p = next;
			continue;
		}
		if (!strcmp(tok, "--in-session")) {
			in_session = 1;
			p = next;
			continue;
		}
		if (!strcmp(tok, "--detach") || !strcmp(tok, "-d")) {
			detach = 1;
			p = next;
			continue;
		}
		if (!strcmp(tok, "--log")) {
			if (!*next) { runas_print_usage(stderr); return 2; }
			p = read_token(next, log_buf, sizeof(log_buf));
			continue;
		}
		if (!strcmp(tok, "-p") || !strcmp(tok, "--password")) {
			if (!*next) { runas_print_usage(stderr); return 2; }
			p = read_token(next, pass_buf, sizeof(pass_buf));
			has_pass = 1;
			continue;
		}
		if (!strcmp(tok, "--user") || !strcmp(tok, "-u")) {
			if (!*next) { runas_print_usage(stderr); return 2; }
			p = read_token(next, user_buf, sizeof(user_buf));
			continue;
		}
		if (!strcmp(tok, "--active")) {
			mode_active = 1;
			p = next;
			if (!is_bg) break;
			continue;
		}
		if (!strcmp(tok, "--session")) {
			char sid_tok[64];
			char *end = NULL;
			unsigned long sid;
			if (!*next) { runas_print_usage(stderr); return 2; }
			p = read_token(next, sid_tok, sizeof(sid_tok));
			sid = strtoul(sid_tok, &end, 10);
			if (!end || end == sid_tok || *end != '\0') {
				fputs("su: --session requires a numeric session ID\n", stderr);
				return 2;
			}
			requested_session = (DWORD)sid;
			in_session = 1;
			if (!is_bg) break;
			continue;
		}
		if (!strcmp(tok, "--")) {
			p = next;
			break;
		}
		if (is_bg) {
			/* For `bg`, first non-flag token starts the command itself! */
			break;
		}
		/* For `su`, first non-flag token is the target username. */
		strncpy(user_buf, tok, sizeof(user_buf) - 1);
		p = next;
		break;
	}

	if (!*p) {
		runas_print_usage(stderr);
		return 2;
	}
	if (is_bg && !mode_active && requested_session == 0xffffffffUL && !user_buf[0] && !has_pass) {
		return runas_bg_current_identity(log_buf[0] ? log_buf : NULL, p);
	}
	if (!mode_active && requested_session == 0xffffffffUL && !user_buf[0]) {
		runas_print_usage(stderr);
		return 2;
	}
	{
		int rc = runas_execute(mode_active, want_admin, in_session, detach,
			log_buf[0] ? log_buf : NULL, requested_session,
			user_buf[0] ? user_buf : NULL, has_pass ? pass_buf : NULL, p);
		SecureZeroMemory(pass_buf, sizeof(pass_buf));
		return rc;
	}
}
#endif
