/* Live System/User environment PATH refresh and target tool discovery. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include <wtsapi32.h>

static HMODULE load_system_dll(const wchar_t *name) {
	wchar_t path[MAX_PATH];
	DWORD len = GetSystemDirectoryW(path, MAX_PATH);
	if (!len || len >= MAX_PATH || len + 1 + wcslen(name) >= MAX_PATH) return NULL;
	path[len++] = L'\\';
	wcscpy(path + len, name);
	return LoadLibraryW(path);
}

static int append_wstr(wchar_t **buf, size_t *used, size_t *cap,
		const wchar_t *text, size_t len) {
	if (*used + len + 1 > *cap) {
		size_t next = *cap ? *cap * 2 : 4096;
		wchar_t *grown;
		while (next < *used + len + 1) next *= 2;
		grown = *buf
			? HeapReAlloc(GetProcessHeap(), 0, *buf, next * sizeof(*grown))
			: HeapAlloc(GetProcessHeap(), 0, next * sizeof(*grown));
		if (!grown) return 0;
		*buf = grown;
		*cap = next;
	}
	if (len) memcpy(*buf + *used, text, len * sizeof(*text));
	*used += len;
	(*buf)[*used] = L'\0';
	return 1;
}

static int path_already_contains(const wchar_t *merged, const wchar_t *seg, size_t seg_len) {
	const wchar_t *p = merged;
	if (!merged || !seg_len) return 0;
	while (*p) {
		const wchar_t *start = p;
		size_t len;
		while (*p && *p != L';') p++;
		len = (size_t)(p - start);
		while (len > 1 && (start[len - 1] == L'\\' || start[len - 1] == L'/')) len--;
		if (len == seg_len && _wcsnicmp(start, seg, len) == 0) return 1;
		if (*p == L';') p++;
	}
	return 0;
}

static void merge_path_string(wchar_t **merged, size_t *used, size_t *cap, const wchar_t *extra) {
	const wchar_t *p = extra;
	if (!extra || !extra[0]) return;
	while (*p) {
		const wchar_t *start;
		size_t len;
		while (*p == L';' || *p == L' ' || *p == L'\t') p++;
		if (!*p) break;
		start = p;
		while (*p && *p != L';') p++;
		len = (size_t)(p - start);
		while (len > 0 && (start[len - 1] == L' ' || start[len - 1] == L'\t')) len--;
		/* Strip surrounding quotes if present. */
		if (len >= 2 && start[0] == L'"' && start[len - 1] == L'"') {
			start++;
			len -= 2;
		}
		while (len > 1 && (start[len - 1] == L'\\' || start[len - 1] == L'/')) len--;
		if (len == 0) continue;
		/* Skip unexpanded %VAR% entries. */
		if (wcschr(start, L'%') && (size_t)(wcschr(start, L'%') - start) < len) continue;
		if (path_already_contains(*merged, start, len)) continue;
		if (*used > 0) {
			if (!append_wstr(merged, used, cap, L";", 1)) return;
		}
		if (!append_wstr(merged, used, cap, start, len)) return;
	}
}

static wchar_t *read_reg_path_value(HKEY root, const wchar_t *subkey) {
	HKEY key = NULL;
	DWORD type = 0, bytes = 0;
	wchar_t *raw = NULL, *expanded = NULL;
	if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS) return NULL;
	if (RegQueryValueExW(key, L"Path", NULL, &type, NULL, &bytes) != ERROR_SUCCESS ||
			(type != REG_SZ && type != REG_EXPAND_SZ) || bytes == 0 || bytes > 131072) {
		RegCloseKey(key);
		return NULL;
	}
	raw = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes + sizeof(wchar_t) * 2);
	if (!raw) { RegCloseKey(key); return NULL; }
	if (RegQueryValueExW(key, L"Path", NULL, &type, (LPBYTE)raw, &bytes) != ERROR_SUCCESS) {
		HeapFree(GetProcessHeap(), 0, raw);
		RegCloseKey(key);
		return NULL;
	}
	RegCloseKey(key);
	if (type == REG_EXPAND_SZ) {
		DWORD need = ExpandEnvironmentStringsW(raw, NULL, 0);
		if (need > 0 && need < 65536) {
			expanded = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need * sizeof(wchar_t));
			if (expanded && ExpandEnvironmentStringsW(raw, expanded, need) > 0) {
				HeapFree(GetProcessHeap(), 0, raw);
				return expanded;
			}
			if (expanded) HeapFree(GetProcessHeap(), 0, expanded);
		}
	}
	return raw;
}

static void merge_interactive_user_path(wchar_t **merged, size_t *used, size_t *cap) {
	typedef DWORD (WINAPI *active_session_fn)(void);
	typedef BOOL (WINAPI *enum_sessions_fn)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW *, DWORD *);
	typedef BOOL (WINAPI *query_user_token_fn)(ULONG, PHANDLE);
	typedef void (WINAPI *wts_free_fn)(PVOID);
	typedef BOOL (WINAPI *create_env_fn)(LPVOID *, HANDLE, BOOL);
	typedef BOOL (WINAPI *destroy_env_fn)(LPVOID);
	HMODULE kernel, wts = NULL, userenv = NULL;
	active_session_fn active_session;
	enum_sessions_fn enum_sessions;
	query_user_token_fn query_user_token;
	wts_free_fn wts_free;
	create_env_fn create_env;
	destroy_env_fn destroy_env;
	HANDLE token = NULL;
	LPVOID block = NULL;
	DWORD sid;

	kernel = GetModuleHandleW(L"kernel32.dll");
	wts = load_system_dll(L"wtsapi32.dll");
	userenv = load_system_dll(L"userenv.dll");
	if (!wts || !userenv) goto done;

	active_session = kernel ? (active_session_fn)(void *)GetProcAddress(kernel, "WTSGetActiveConsoleSessionId") : NULL;
	enum_sessions = (enum_sessions_fn)(void *)GetProcAddress(wts, "WTSEnumerateSessionsW");
	query_user_token = (query_user_token_fn)(void *)GetProcAddress(wts, "WTSQueryUserToken");
	wts_free = (wts_free_fn)(void *)GetProcAddress(wts, "WTSFreeMemory");
	create_env = (create_env_fn)(void *)GetProcAddress(userenv, "CreateEnvironmentBlock");
	destroy_env = (destroy_env_fn)(void *)GetProcAddress(userenv, "DestroyEnvironmentBlock");
	if (!query_user_token || !create_env || !destroy_env) goto done;

	if (active_session) {
		sid = active_session();
		if (sid != 0 && sid != 0xffffffffUL) {
			query_user_token(sid, &token);
		}
	}
	if (!token && enum_sessions && wts_free) {
		PWTS_SESSION_INFOW sessions = NULL;
		DWORD count = 0, i;
		if (enum_sessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count) && sessions) {
			for (i = 0; i < count && !token; i++) {
				if (sessions[i].SessionId == 0) continue;
				if (sessions[i].State == WTSActive || sessions[i].State == WTSConnected) {
					query_user_token(sessions[i].SessionId, &token);
				}
			}
			for (i = 0; i < count && !token; i++) {
				if (sessions[i].SessionId == 0) continue;
				if (sessions[i].State == WTSDisconnected) {
					query_user_token(sessions[i].SessionId, &token);
				}
			}
			wts_free(sessions);
		}
	}
	if (!token) goto done;
	if (!create_env(&block, token, FALSE) || !block) goto done;
	{
		const wchar_t *p;
		for (p = (const wchar_t *)block; *p; p += wcslen(p) + 1) {
			if (_wcsnicmp(p, L"PATH=", 5) == 0) {
				merge_path_string(merged, used, cap, p + 5);
				break;
			}
		}
	}
	destroy_env(block);

done:
	if (token) CloseHandle(token);
	if (userenv) FreeLibrary(userenv);
	if (wts) FreeLibrary(wts);
}

/* Build a deduplicated PATH combining:
 *   1. Live System Registry Path (HKLM\...\Environment)
 *   2. Live Current User Registry Path (HKCU\Environment)
 *   3. Logged-on Interactive User Path (when running as SYSTEM/service)
 *   4. Current process inherited PATH
 * Caller frees the returned buffer with HeapFree(GetProcessHeap(), 0, ptr). */
wchar_t *dropbear_win_build_merged_path(const wchar_t *inherited_path) {
	wchar_t *merged = NULL;
	size_t used = 0, cap = 0;
	wchar_t *sys_path = read_reg_path_value(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");
	wchar_t *usr_path = read_reg_path_value(HKEY_CURRENT_USER, L"Environment");

	/* Keep inherited process PATH first if explicitly overridden, or System -> User -> Inherited. */
	if (sys_path) {
		merge_path_string(&merged, &used, &cap, sys_path);
		HeapFree(GetProcessHeap(), 0, sys_path);
	}
	if (usr_path) {
		merge_path_string(&merged, &used, &cap, usr_path);
		HeapFree(GetProcessHeap(), 0, usr_path);
	}
	merge_interactive_user_path(&merged, &used, &cap);
	if (inherited_path && inherited_path[0]) {
		merge_path_string(&merged, &used, &cap, inherited_path);
	}
	if (!merged) {
		append_wstr(&merged, &used, &cap, L"", 0);
	}
	return merged;
}

struct tool_spec {
	const char *name;
	const wchar_t *filename;
};

static const struct tool_spec KNOWN_TOOLS[] = {
	{ "cmd", L"cmd.exe" },
	{ "powershell", L"powershell.exe" },
	{ "pwsh", L"pwsh.exe" },
	{ "python", L"python.exe" },
	{ "python3", L"python3.exe" },
	{ "py", L"py.exe" },
	{ "node", L"node.exe" },
	{ "npm", L"npm.cmd" },
	{ "bun", L"bun.exe" },
	{ "deno", L"deno.exe" },
	{ "uv", L"uv.exe" },
	{ "pip", L"pip.exe" },
	{ "git", L"git.exe" },
	{ "gh", L"gh.exe" },
	{ "bash", L"bash.exe" },
	{ "curl", L"curl.exe" },
	{ "tar", L"tar.exe" },
	{ "7z", L"7z.exe" },
	{ "ffmpeg", L"ffmpeg.exe" },
	{ "ssh", L"ssh.exe" },
	{ "scp", L"scp.exe" },
	{ "gcc", L"gcc.exe" },
	{ "clang", L"clang.exe" },
	{ "cl", L"cl.exe" },
	{ "cmake", L"cmake.exe" },
	{ "make", L"make.exe" },
	{ "ninja", L"ninja.exe" },
	{ "go", L"go.exe" },
	{ "cargo", L"cargo.exe" },
	{ "rustc", L"rustc.exe" },
	{ "dotnet", L"dotnet.exe" },
	{ "java", L"java.exe" },
	{ "javac", L"javac.exe" },
	{ "winget", L"winget.exe" },
	{ "choco", L"choco.exe" },
	{ "scoop", L"scoop.cmd" },
	{ "docker", L"docker.exe" },
	{ "kubectl", L"kubectl.exe" },
	{ "sqlite3", L"sqlite3.exe" },
};

static wchar_t *get_current_process_path_env(void) {
	DWORD need = GetEnvironmentVariableW(L"PATH", NULL, 0);
	wchar_t *buf;
	if (!need || need > 65536) return NULL;
	buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need * sizeof(wchar_t));
	if (!buf) return NULL;
	if (GetEnvironmentVariableW(L"PATH", buf, need) == 0) {
		HeapFree(GetProcessHeap(), 0, buf);
		return NULL;
	}
	return buf;
}

static int resolve_tool_on_path(const wchar_t *search_path, const wchar_t *filename,
		wchar_t *resolved, DWORD cap) {
	DWORD n, attrs;
	if (!search_path || !search_path[0]) return 0;
	n = SearchPathW(search_path, filename, NULL, cap, resolved, NULL);
	if (!n || n >= cap) return 0;
	attrs = GetFileAttributesW(resolved);
	if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) return 0;
	return 1;
}

static void print_json_escaped(FILE *stream, const char *s) {
	fputc('"', stream);
	for (; s && *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\') { fputc('\\', stream); fputc(c, stream); }
		else if (c == '\b') fputs("\\b", stream);
		else if (c == '\f') fputs("\\f", stream);
		else if (c == '\n') fputs("\\n", stream);
		else if (c == '\r') fputs("\\r", stream);
		else if (c == '\t') fputs("\\t", stream);
		else if (c < 0x20) fprintf(stream, "\\u%04x", c);
		else fputc(c, stream);
	}
	fputc('"', stream);
}

void dropbear_win_print_tools_json(FILE *stream) {
	wchar_t *inherited = get_current_process_path_env();
	wchar_t *merged = dropbear_win_build_merged_path(inherited);
	wchar_t exe[MAX_PATH], resolved[MAX_PATH];
	char utf8[MAX_PATH * 3];
	size_t i;
	int first = 1;

	fputc('{', stream);
	if (GetModuleFileNameW(NULL, exe, MAX_PATH) &&
			WideCharToMultiByte(CP_UTF8, 0, exe, -1, utf8, sizeof(utf8), NULL, NULL)) {
		char qjs_cmd[MAX_PATH * 3 + 16];
		snprintf(qjs_cmd, sizeof(qjs_cmd), "%s --qjs", utf8);
		fputs("\"qjs\":", stream);
		print_json_escaped(stream, qjs_cmd);
		first = 0;
	}
	if (merged && merged[0]) {
		for (i = 0; i < sizeof(KNOWN_TOOLS) / sizeof(KNOWN_TOOLS[0]); i++) {
			if (!resolve_tool_on_path(merged, KNOWN_TOOLS[i].filename, resolved, MAX_PATH))
				continue;
			if (!WideCharToMultiByte(CP_UTF8, 0, resolved, -1, utf8, sizeof(utf8), NULL, NULL))
				continue;
			if (!first) fputc(',', stream);
			print_json_escaped(stream, KNOWN_TOOLS[i].name);
			fputc(':', stream);
			print_json_escaped(stream, utf8);
			first = 0;
		}
		/* Optional user-configured extra tools: DROPBEAR_WIN_EXTRA_TOOLS=tool1.exe;tool2.exe */
		{
			wchar_t extra[2048];
			DWORD elen = GetEnvironmentVariableW(L"DROPBEAR_WIN_EXTRA_TOOLS", extra, 2048);
			if (elen > 0 && elen < 2048) {
				wchar_t *p = extra;
				while (*p) {
					wchar_t *start;
					size_t len;
					wchar_t item[128];
					char key[256];
					while (*p == L';' || *p == L',' || *p == L' ' || *p == L'\t') p++;
					if (!*p) break;
					start = p;
					while (*p && *p != L';' && *p != L',') p++;
					len = (size_t)(p - start);
					while (len > 0 && (start[len - 1] == L' ' || start[len - 1] == L'\t')) len--;
					if (len == 0 || len >= 120) continue;
					memcpy(item, start, len * sizeof(wchar_t));
					item[len] = L'\0';
					if (!resolve_tool_on_path(merged, item, resolved, MAX_PATH)) continue;
					if (!WideCharToMultiByte(CP_UTF8, 0, item, -1, key, sizeof(key), NULL, NULL)) continue;
					if (!WideCharToMultiByte(CP_UTF8, 0, resolved, -1, utf8, sizeof(utf8), NULL, NULL)) continue;
					if (!first) fputc(',', stream);
					print_json_escaped(stream, key);
					fputc(':', stream);
					print_json_escaped(stream, utf8);
					first = 0;
				}
			}
		}
	}
	fputc('}', stream);
	if (merged) HeapFree(GetProcessHeap(), 0, merged);
	if (inherited) HeapFree(GetProcessHeap(), 0, inherited);
}

void dropbear_win_format_tools_summary(char *output, size_t output_size, const wchar_t *search_path) {
	wchar_t *owned_path = NULL;
	wchar_t resolved[MAX_PATH];
	size_t used = 0, i;
	int count = 0;

	if (!output || output_size == 0) return;
	output[0] = '\0';
	if (!search_path || !search_path[0]) {
		wchar_t *inherited = get_current_process_path_env();
		owned_path = dropbear_win_build_merged_path(inherited);
		if (inherited) HeapFree(GetProcessHeap(), 0, inherited);
		search_path = owned_path;
	}

	used += (size_t)snprintf(output + used, output_size - used, "qjs (embedded)");
	count++;
	if (search_path && search_path[0]) {
		for (i = 0; i < sizeof(KNOWN_TOOLS) / sizeof(KNOWN_TOOLS[0]); i++) {
			int n;
			if (!resolve_tool_on_path(search_path, KNOWN_TOOLS[i].filename, resolved, MAX_PATH))
				continue;
			if (used + strlen(KNOWN_TOOLS[i].name) + 4 >= output_size) break;
			n = snprintf(output + used, output_size - used, ", %s", KNOWN_TOOLS[i].name);
			if (n > 0) used += (size_t)n;
			count++;
		}
	}
	if (owned_path) HeapFree(GetProcessHeap(), 0, owned_path);
	(void)count;
}
#endif
