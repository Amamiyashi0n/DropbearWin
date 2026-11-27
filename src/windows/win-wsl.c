/* Embedded wsl-bridge support for Dropbear-win (NT 5.1/5.2 compatible imports only). */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include "win-account.h"

#define IDR_WSL_BRIDGE_EXE 101

static int wsl_get_embedded_resource(const unsigned char **out_data, DWORD *out_size) {
	HRSRC res = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_WSL_BRIDGE_EXE), MAKEINTRESOURCEW(10));
	HGLOBAL hglob;
	const unsigned char *ptr;
	DWORD sz;
	if (!res) return 0;
	sz = SizeofResource(NULL, res);
	if (sz < 64) return 0;
	hglob = LoadResource(NULL, res);
	if (!hglob) return 0;
	ptr = (const unsigned char *)LockResource(hglob);
	if (!ptr) return 0;
	*out_data = ptr;
	*out_size = sz;
	return 1;
}

int dropbear_win_wsl_has_embedded(void) {
	const unsigned char *data = NULL;
	DWORD size = 0;
	return wsl_get_embedded_resource(&data, &size);
}

static int wsl_file_matches_bytes(const wchar_t *path, const unsigned char *data, DWORD size) {
	HANDLE h = CreateFileW(path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD hi = 0, lo, total = 0, nread = 0;
	unsigned char buf[16384];
	int ok = 0;
	if (h == INVALID_HANDLE_VALUE) return 0;
	lo = GetFileSize(h, &hi);
	if (hi != 0 || lo != size) {
		CloseHandle(h);
		return 0;
	}
	ok = 1;
	while (total < size) {
		DWORD chunk = size - total;
		if (chunk > sizeof(buf)) chunk = sizeof(buf);
		if (!ReadFile(h, buf, chunk, &nread, NULL) || nread != chunk) {
			ok = 0;
			break;
		}
		if (memcmp(buf, data + total, chunk) != 0) {
			ok = 0;
			break;
		}
		total += chunk;
	}
	CloseHandle(h);
	return ok;
}

static int wsl_write_resource_file(const wchar_t *target_path, const unsigned char *data, DWORD size) {
	wchar_t tmp_path[MAX_PATH];
	HANDLE h;
	DWORD total = 0, written = 0;
	int n;

	if (wsl_file_matches_bytes(target_path, data, size)) {
		return 1;
	}
	n = _snwprintf(tmp_path, MAX_PATH, L"%ls.wsltmp-%lu", target_path, (unsigned long)GetCurrentProcessId());
	if (n <= 0 || n >= MAX_PATH) return 0;

	h = CreateFileW(tmp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		/* If target already exists (e.g. non-writable Program Files for unprivileged user), reuse it. */
		DWORD attrs = GetFileAttributesW(target_path);
		return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) ? 1 : 0;
	}
	while (total < size) {
		DWORD chunk = size - total;
		if (!WriteFile(h, data + total, chunk, &written, NULL) || written == 0) {
			CloseHandle(h);
			DeleteFileW(tmp_path);
			return 0;
		}
		total += written;
	}
	FlushFileBuffers(h);
	CloseHandle(h);

	if (!MoveFileExW(tmp_path, target_path, MOVEFILE_REPLACE_EXISTING)) {
		DeleteFileW(tmp_path);
		/* Target may currently be running; reuse existing binary if present. */
		DWORD attrs = GetFileAttributesW(target_path);
		return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) ? 1 : 0;
	}
	return 1;
}

int dropbear_win_wsl_extract_to_dir(const wchar_t *directory, int also_shims) {
	const unsigned char *data = NULL;
	DWORD size = 0;
	wchar_t path[MAX_PATH];
	int n;

	if (!directory || !directory[0]) return 0;
	if (!wsl_get_embedded_resource(&data, &size)) return 0;
	CreateDirectoryW(directory, NULL);

	n = _snwprintf(path, MAX_PATH, L"%ls\\wsl-bridge.exe", directory);
	if (n <= 0 || n >= MAX_PATH) return 0;
	if (!wsl_write_resource_file(path, data, size)) return 0;

	if (also_shims) {
		n = _snwprintf(path, MAX_PATH, L"%ls\\bash.exe", directory);
		if (n > 0 && n < MAX_PATH) wsl_write_resource_file(path, data, size);
		n = _snwprintf(path, MAX_PATH, L"%ls\\sh.exe", directory);
		if (n > 0 && n < MAX_PATH) wsl_write_resource_file(path, data, size);
	}
	return 1;
}

static int wsl_resolve_executable(wchar_t *out_path, DWORD out_cap) {
	const unsigned char *data = NULL;
	DWORD size = 0;
	wchar_t mod_dir[MAX_PATH], candidate[MAX_PATH], *slash;
	DWORD len, attrs;

	if (wsl_get_embedded_resource(&data, &size)) {
		/* 1. Try beside current DropbearWin EXE (e.g. C:\Program Files\DropbearWin\wsl-bridge.exe) */
		len = GetModuleFileNameW(NULL, mod_dir, MAX_PATH);
		if (len > 0 && len < MAX_PATH && (slash = wcsrchr(mod_dir, L'\\')) != NULL) {
			*slash = L'\0';
			if (_snwprintf(candidate, MAX_PATH, L"%ls\\wsl-bridge.exe", mod_dir) > 0 &&
					wsl_write_resource_file(candidate, data, size)) {
				if (wcslen(candidate) < out_cap) {
					wcscpy(out_path, candidate);
					return 1;
				}
			}
		}
		/* 2. Fallback: DropbearWin data dir */
		{
			wchar_t data_dir[MAX_PATH];
			if (MultiByteToWideChar(CP_ACP, 0, dropbear_win_data_dir(), -1, data_dir, MAX_PATH) > 0) {
				CreateDirectoryW(data_dir, NULL);
				if (_snwprintf(candidate, MAX_PATH, L"%ls\\wsl-bridge.exe", data_dir) > 0 &&
						wsl_write_resource_file(candidate, data, size)) {
					if (wcslen(candidate) < out_cap) {
						wcscpy(out_path, candidate);
						return 1;
					}
				}
			}
		}
		/* 3. Fallback: Temp dir */
		len = GetTempPathW(MAX_PATH, mod_dir);
		if (len > 0 && len < MAX_PATH) {
			if (mod_dir[len - 1] == L'\\') mod_dir[len - 1] = L'\0';
			if (_snwprintf(candidate, MAX_PATH, L"%ls\\dropbear-win-wsl-bridge.exe", mod_dir) > 0 &&
					wsl_write_resource_file(candidate, data, size)) {
				if (wcslen(candidate) < out_cap) {
					wcscpy(out_path, candidate);
					return 1;
				}
			}
		}
	}

	/* Fallback for non-embedded builds (e.g. x86): check standard system install and PATH */
	attrs = GetFileAttributesW(L"C:\\Program Files\\wsl-bridge\\wsl-bridge.exe");
	if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
		if (wcslen(L"C:\\Program Files\\wsl-bridge\\wsl-bridge.exe") < out_cap) {
			wcscpy(out_path, L"C:\\Program Files\\wsl-bridge\\wsl-bridge.exe");
			return 1;
		}
	}
	if (SearchPathW(NULL, L"wsl-bridge.exe", NULL, out_cap, out_path, NULL) > 0) {
		return 1;
	}
	return 0;
}

static wchar_t *wsl_utf8_to_wide(const char *s) {
	int need;
	wchar_t *out;
	if (!s) s = "";
	need = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
	if (need <= 0) need = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
	if (need <= 0) return NULL;
	out = HeapAlloc(GetProcessHeap(), 0, (size_t)need * sizeof(wchar_t));
	if (!out) return NULL;
	if (MultiByteToWideChar(CP_UTF8, 0, s, -1, out, need) <= 0) {
		if (MultiByteToWideChar(CP_ACP, 0, s, -1, out, need) <= 0) {
			HeapFree(GetProcessHeap(), 0, out);
			return NULL;
		}
	}
	return out;
}

static int wsl_append_wchars(wchar_t **buf, size_t *used, size_t *cap, const wchar_t *s, size_t n) {
	if (*used + n + 1 > *cap) {
		size_t new_cap = (*cap == 0) ? 512 : (*cap * 2);
		wchar_t *grown;
		while (new_cap < *used + n + 1) new_cap *= 2;
		grown = *buf
			? HeapReAlloc(GetProcessHeap(), 0, *buf, new_cap * sizeof(wchar_t))
			: HeapAlloc(GetProcessHeap(), 0, new_cap * sizeof(wchar_t));
		if (!grown) return 0;
		*buf = grown;
		*cap = new_cap;
	}
	if (n > 0) memcpy(*buf + *used, s, n * sizeof(wchar_t));
	*used += n;
	(*buf)[*used] = L'\0';
	return 1;
}

static int wsl_append_quoted_arg(wchar_t **buf, size_t *used, size_t *cap, const wchar_t *arg) {
	int need_quotes = 0;
	const wchar_t *p;
	if (!arg[0]) need_quotes = 1;
	for (p = arg; *p; p++) {
		if (*p == L' ' || *p == L'\t' || *p == L'"' || *p == L'\n' || *p == L'\r') {
			need_quotes = 1;
			break;
		}
	}
	if (!need_quotes) {
		return wsl_append_wchars(buf, used, cap, arg, wcslen(arg));
	}
	if (!wsl_append_wchars(buf, used, cap, L"\"", 1)) return 0;
	for (p = arg; *p; ) {
		size_t bs = 0;
		while (*p == L'\\') { bs++; p++; }
		if (*p == L'\0') {
			size_t k;
			for (k = 0; k < bs * 2; k++)
				if (!wsl_append_wchars(buf, used, cap, L"\\", 1)) return 0;
			break;
		} else if (*p == L'"') {
			size_t k;
			for (k = 0; k < bs * 2 + 1; k++)
				if (!wsl_append_wchars(buf, used, cap, L"\\", 1)) return 0;
			if (!wsl_append_wchars(buf, used, cap, L"\"", 1)) return 0;
			p++;
		} else {
			size_t k;
			for (k = 0; k < bs; k++)
				if (!wsl_append_wchars(buf, used, cap, L"\\", 1)) return 0;
			if (!wsl_append_wchars(buf, used, cap, p, 1)) return 0;
			p++;
		}
	}
	return wsl_append_wchars(buf, used, cap, L"\"", 1);
}

static int wsl_run_wide_argv(int argc, wchar_t **wargv) {
	wchar_t exe[MAX_PATH];
	wchar_t *cmdline = NULL;
	size_t used = 0, cap = 0;
	int i;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD exit_code = 1;

	if (!wsl_resolve_executable(exe, MAX_PATH)) {
		fputs("wsl-bridge: embedded binary unavailable and wsl-bridge.exe not found.\n", stderr);
		return 127;
	}
	if (!wsl_append_quoted_arg(&cmdline, &used, &cap, exe)) return 1;
	for (i = 0; i < argc; i++) {
		if (!wsl_append_wchars(&cmdline, &used, &cap, L" ", 1) ||
				!wsl_append_quoted_arg(&cmdline, &used, &cap, wargv[i])) {
			HeapFree(GetProcessHeap(), 0, cmdline);
			return 1;
		}
	}

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

	if (!CreateProcessW(exe, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		fprintf(stderr, "wsl-bridge: CreateProcessW failed (error %lu).\n", (unsigned long)GetLastError());
		HeapFree(GetProcessHeap(), 0, cmdline);
		return 1;
	}
	HeapFree(GetProcessHeap(), 0, cmdline);
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &exit_code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return (int)exit_code;
}

static void wsl_print_json_path(FILE *stream, const wchar_t *wpath) {
	char utf8[MAX_PATH * 3];
	const char *s;
	if (!WideCharToMultiByte(CP_UTF8, 0, wpath, -1, utf8, sizeof(utf8), NULL, NULL)) {
		fputs("\"\"", stream);
		return;
	}
	fputc('"', stream);
	for (s = utf8; *s; s++) {
		if (*s == '"' || *s == '\\') fputc('\\', stream);
		fputc(*s, stream);
	}
	fputc('"', stream);
}

int dropbear_win_wsl_main(int argc, char **argv) {
	wchar_t **wargv = NULL;
	int i, ret;

	if (argc >= 2 && (!strcmp(argv[1], "--extract") || !strcmp(argv[1], "--install-shims"))) {
		int shims = !strcmp(argv[1], "--install-shims");
		wchar_t dir[MAX_PATH];
		const unsigned char *data = NULL;
		DWORD size = 0;
		if (argc >= 3 && argv[2][0]) {
			wchar_t *wdir = wsl_utf8_to_wide(argv[2]);
			if (!wdir || wcslen(wdir) >= MAX_PATH) {
				if (wdir) HeapFree(GetProcessHeap(), 0, wdir);
				return 2;
			}
			wcscpy(dir, wdir);
			HeapFree(GetProcessHeap(), 0, wdir);
		} else if (shims) {
			wcscpy(dir, L"C:\\Program Files\\wsl-bridge");
		} else {
			wchar_t *slash;
			DWORD len = GetModuleFileNameW(NULL, dir, MAX_PATH);
			if (!len || len >= MAX_PATH || !(slash = wcsrchr(dir, L'\\'))) return 1;
			*slash = L'\0';
		}
		if (!wsl_get_embedded_resource(&data, &size)) {
			fputs("{\"ok\":false,\"error\":\"no embedded wsl-bridge resource in this build\"}\n", stdout);
			return 1;
		}
		if (!dropbear_win_wsl_extract_to_dir(dir, shims)) {
			fputs("{\"ok\":false,\"error\":\"failed to extract wsl-bridge\"}\n", stdout);
			return 1;
		}
		fputs("{\"ok\":true,\"directory\":", stdout);
		wsl_print_json_path(stdout, dir);
		fprintf(stdout, ",\"shims\":%s,\"bytes\":%lu}\n", shims ? "true" : "false", (unsigned long)size);
		return 0;
	}

	/* Forward remaining args to embedded wsl-bridge.exe */
	wargv = calloc((size_t)(argc + 1), sizeof(wchar_t *));
	if (!wargv) return 1;
	for (i = 1; i < argc; i++) {
		wargv[i - 1] = wsl_utf8_to_wide(argv[i]);
		if (!wargv[i - 1]) {
			int j;
			for (j = 0; j < i - 1; j++) HeapFree(GetProcessHeap(), 0, wargv[j]);
			free(wargv);
			return 1;
		}
	}
	ret = wsl_run_wide_argv(argc - 1, wargv);
	for (i = 0; i < argc - 1; i++) HeapFree(GetProcessHeap(), 0, wargv[i]);
	free(wargv);
	return ret;
}

/* Match direct SSH exec commands: `wsl-bridge ...` or `wsl-bash ...`
 * when no unquoted CMD shell chaining operators are present. */
int dropbear_win_is_wsl_command(const char *command) {
	const char *p;
	char quote = 0;
	size_t cmd_len;
	if (!command) return 0;
	cmd_len = strlen(command);
	if (cmd_len == 0 || cmd_len > 60000) return 0;
	p = command;
	while (*p == ' ' || *p == '\t') p++;
	if (strncmp(p, "wsl-bridge", 10) == 0 && (p[10] == '\0' || p[10] == ' ' || p[10] == '\t')) {
		p += 10;
	} else if (strncmp(p, "wsl-bash", 8) == 0 && (p[8] == '\0' || p[8] == ' ' || p[8] == '\t')) {
		p += 8;
	} else {
		return 0;
	}
	for (; *p; p++) {
		char c = *p;
		if (c == '\r' || c == '\n') return 0;
		if (quote) {
			if (c == '\\' && quote == '"' && p[1]) { p++; continue; }
			if (c == quote) quote = 0;
			continue;
		}
		if (c == '"' || c == '\'') { quote = c; continue; }
		if (c == '&' || c == '|' || c == '<' || c == '>' || c == '%' || c == '^') return 0;
	}
	return quote == 0;
}

int dropbear_win_wsl_exec_command(const char *command) {
	size_t len = strlen(command);
	char *copy = malloc(len + 1);
	char **argv = calloc(len / 2 + 8, sizeof(char *));
	wchar_t **wargv = NULL;
	int argc = 0, wargc = 0, i, is_wsl_bash = 0, result = 1;
	const char *src = command;
	char *dst;

	if (!copy || !argv) {
		free(copy);
		free(argv);
		return 1;
	}
	dst = copy;
	while (*src) {
		char quote = 0;
		while (*src == ' ' || *src == '\t') src++;
		if (!*src) break;
		argv[argc++] = dst;
		while (*src) {
			if (quote) {
				if (quote == '"' && *src == '\\' && (src[1] == '"' || src[1] == '\\')) {
					src++;
					*dst++ = *src++;
					continue;
				}
				if (*src == quote) { quote = 0; src++; continue; }
				*dst++ = *src++;
				continue;
			}
			if (*src == ' ' || *src == '\t') break;
			if (*src == '"' || *src == '\'') { quote = *src++; continue; }
			*dst++ = *src++;
		}
		*dst++ = '\0';
	}
	argv[argc] = NULL;
	if (argc == 0) {
		free(argv);
		free(copy);
		return 2;
	}
	if (!strcmp(argv[0], "wsl-bash")) is_wsl_bash = 1;

	wargv = calloc((size_t)(argc + 2), sizeof(wchar_t *));
	if (!wargv) {
		free(argv);
		free(copy);
		return 1;
	}
	if (is_wsl_bash) {
		wargv[wargc++] = wsl_utf8_to_wide("bash");
	}
	for (i = 1; i < argc; i++) {
		wargv[wargc] = wsl_utf8_to_wide(argv[i]);
		if (!wargv[wargc]) goto cleanup;
		wargc++;
	}
	result = wsl_run_wide_argv(wargc, wargv);

cleanup:
	for (i = 0; i < wargc; i++) {
		if (wargv[i]) HeapFree(GetProcessHeap(), 0, wargv[i]);
	}
	free(wargv);
	free(argv);
	free(copy);
	return result;
}
#endif
