/* Embedded wsl-bridge + automatic WSL detection & built-in supervisor for Dropbear-win.
 * Uses only NT 5.1/5.2 static imports (kernel32, advapi32, ws2_32, msvcrt);
 * optional Vista+/Win10 APIs (wtsapi32, userenv, secur32, sddl) are loaded dynamically. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include "win-account.h"
#include <wtsapi32.h>

#define IDR_WSL_BRIDGE_EXE 101
#define WSL_SHARED_DIR L"C:\\ProgramData\\wsl-bridge"
#define WSL_OWNER_CONF L"C:\\ProgramData\\wsl-bridge\\wsl-owner.conf"
#define WSL_BROKER_JSON L"C:\\ProgramData\\wsl-bridge\\broker.json"

struct wsl_host_info {
	int available;
	int running_as_system;
	wchar_t distro[128];
	wchar_t owner_sid[128];
	wchar_t owner_domain[256];
	wchar_t owner_user[256];
	DWORD default_uid;
};

/* Minimal dynamic definitions for userenv / secur32 / S4U (avoid extra headers/imports). */
typedef struct _WSL_PROFILEINFOW {
	DWORD dwSize;
	DWORD dwFlags;
	LPWSTR lpUserName;
	LPWSTR lpProfilePath;
	LPWSTR lpDefaultPath;
	LPWSTR lpServerName;
	LPWSTR lpPolicyPath;
	HANDLE hProfile;
} WSL_PROFILEINFOW;

typedef struct _WSL_LSA_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} WSL_LSA_STRING;

typedef struct _WSL_LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} WSL_LSA_UNICODE_STRING;

typedef struct _WSL_MSV1_0_S4U_LOGON {
	ULONG MessageType; /* 12 = MsV1_0S4ULogon */
	ULONG Flags;
	WSL_LSA_UNICODE_STRING UserPrincipalName;
	WSL_LSA_UNICODE_STRING DomainName;
} WSL_MSV1_0_S4U_LOGON;

typedef struct _WSL_TOKEN_SOURCE {
	CHAR SourceName[8];
	LUID SourceIdentifier;
} WSL_TOKEN_SOURCE;

typedef LONG (NTAPI *lsa_connect_untrusted_fn)(PHANDLE);
typedef LONG (NTAPI *lsa_register_logon_fn)(WSL_LSA_STRING *, PHANDLE, ULONG *);
typedef LONG (NTAPI *lsa_lookup_pkg_fn)(HANDLE, WSL_LSA_STRING *, PULONG);
typedef LONG (NTAPI *lsa_logon_user_fn)(HANDLE, WSL_LSA_STRING *, ULONG, ULONG,
	PVOID, ULONG, PTOKEN_GROUPS, WSL_TOKEN_SOURCE *, PVOID *, PULONG, PLUID, PHANDLE, PVOID, PLONG);
typedef LONG (NTAPI *lsa_free_buf_fn)(PVOID);
typedef LONG (NTAPI *lsa_deregister_fn)(HANDLE);

static HMODULE wsl_load_system_dll(const wchar_t *name) {
	wchar_t path[MAX_PATH];
	DWORD len = GetSystemDirectoryW(path, MAX_PATH);
	if (!len || len + wcslen(name) + 2 >= MAX_PATH) return NULL;
	wcscat(path, L"\\");
	wcscat(path, name);
	return LoadLibraryW(path);
}

static void wsl_enable_privilege(const wchar_t *priv_name) {
	HANDLE token = NULL;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		return;
	if (LookupPrivilegeValueW(NULL, priv_name, &luid)) {
		memset(&tp, 0, sizeof(tp));
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
	}
	CloseHandle(token);
}

static int wsl_is_current_process_system(void) {
	HANDLE token = NULL;
	unsigned char buf[256];
	DWORD needed = 0;
	TOKEN_USER *tu;
	SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
	PSID sys_sid = NULL;
	int is_sys = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
	if (GetTokenInformation(token, TokenUser, buf, sizeof(buf), &needed)) {
		tu = (TOKEN_USER *)buf;
		if (AllocateAndInitializeSid(&nt_auth, 1, SECURITY_LOCAL_SYSTEM_RID,
				0, 0, 0, 0, 0, 0, 0, &sys_sid)) {
			if (EqualSid(tu->User.Sid, sys_sid)) is_sys = 1;
			FreeSid(sys_sid);
		}
	}
	CloseHandle(token);
	return is_sys;
}

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

/* ---------------- Automatic WSL Host Detection ---------------- */

static int wsl_read_lxss_key(HKEY root_key, const wchar_t *subpath,
		wchar_t *distro_out, size_t distro_cap, DWORD *uid_out) {
	HKEY lxss = NULL, dk = NULL;
	wchar_t def_guid[128] = {0};
	wchar_t dname[128] = {0};
	DWORD cb, type, uid = 0;
	int found = 0;

	if (RegOpenKeyExW(root_key, subpath, 0, KEY_READ, &lxss) != ERROR_SUCCESS)
		return 0;

	cb = sizeof(def_guid);
	if (RegQueryValueExW(lxss, L"DefaultDistribution", NULL, &type, (LPBYTE)def_guid, &cb) == ERROR_SUCCESS &&
			(type == REG_SZ || type == REG_EXPAND_SZ) && def_guid[0]) {
		if (RegOpenKeyExW(lxss, def_guid, 0, KEY_READ, &dk) == ERROR_SUCCESS) {
			cb = sizeof(dname);
			if (RegQueryValueExW(dk, L"DistributionName", NULL, &type, (LPBYTE)dname, &cb) == ERROR_SUCCESS &&
					type == REG_SZ && dname[0]) {
				cb = sizeof(uid);
				RegQueryValueExW(dk, L"DefaultUid", NULL, &type, (LPBYTE)&uid, &cb);
				found = 1;
			}
			RegCloseKey(dk);
		}
	}

	/* Fallback: pick first subkey that has a DistributionName */
	if (!found) {
		DWORD idx = 0;
		for (;; idx++) {
			wchar_t sub[128];
			DWORD sub_len = 128;
			if (RegEnumKeyExW(lxss, idx, sub, &sub_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
				break;
			if (RegOpenKeyExW(lxss, sub, 0, KEY_READ, &dk) == ERROR_SUCCESS) {
				cb = sizeof(dname);
				if (RegQueryValueExW(dk, L"DistributionName", NULL, &type, (LPBYTE)dname, &cb) == ERROR_SUCCESS &&
						type == REG_SZ && dname[0]) {
					cb = sizeof(uid);
					RegQueryValueExW(dk, L"DefaultUid", NULL, &type, (LPBYTE)&uid, &cb);
					found = 1;
				}
				RegCloseKey(dk);
				if (found) break;
			}
		}
	}

	RegCloseKey(lxss);
	if (found) {
		wcsncpy(distro_out, dname, distro_cap - 1);
		distro_out[distro_cap - 1] = L'\0';
		if (uid_out) *uid_out = uid;
	}
	return found;
}

static int wsl_sid_string_to_account(const wchar_t *sid_str,
		wchar_t *domain_out, DWORD domain_cap, wchar_t *user_out, DWORD user_cap) {
	typedef BOOL (WINAPI *conv_sid_fn)(LPCWSTR, PSID *);
	HMODULE adv = GetModuleHandleW(L"advapi32.dll");
	conv_sid_fn conv_sid;
	PSID psid = NULL;
	SID_NAME_USE use;
	DWORD ulen = user_cap, dlen = domain_cap;
	int ok = 0;

	if (!adv) adv = wsl_load_system_dll(L"advapi32.dll");
	if (!adv) return 0;
	conv_sid = (conv_sid_fn)(void *)GetProcAddress(adv, "ConvertStringSidToSidW");
	if (!conv_sid || !conv_sid(sid_str, &psid) || !psid) return 0;
	if (LookupAccountSidW(NULL, psid, user_out, &ulen, domain_out, &dlen, &use)) {
		ok = 1;
	}
	LocalFree(psid);
	return ok;
}

static void wsl_ensure_shared_dir_acl(const wchar_t *owner_sid) {
	typedef BOOL (WINAPI *conv_sddl_fn)(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR *, PULONG);
	typedef DWORD (WINAPI *set_named_sec_fn)(LPWSTR, DWORD, SECURITY_INFORMATION, PSID, PSID, PACL, PACL);
	wchar_t tmp_dir[MAX_PATH];
	CreateDirectoryW(WSL_SHARED_DIR, NULL);
	_snwprintf(tmp_dir, MAX_PATH, L"%ls\\tmp", WSL_SHARED_DIR);
	CreateDirectoryW(tmp_dir, NULL);

	if (!owner_sid || !owner_sid[0]) return;
	{
		HMODULE adv = GetModuleHandleW(L"advapi32.dll");
		conv_sddl_fn conv_sddl;
		set_named_sec_fn set_sec;
		wchar_t sddl[512];
		PSECURITY_DESCRIPTOR sd = NULL;
		BOOL dacl_present = FALSE, dacl_defaulted = FALSE;
		PACL dacl = NULL;
		if (!adv) return;
		conv_sddl = (conv_sddl_fn)(void *)GetProcAddress(adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW");
		set_sec = (set_named_sec_fn)(void *)GetProcAddress(adv, "SetNamedSecurityInfoW");
		if (!conv_sddl || !set_sec) return;
		_snwprintf(sddl, 512, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%ls)", owner_sid);
		if (conv_sddl(sddl, 1 /* SDDL_REVISION_1 */, &sd, NULL) && sd) {
			if (GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted) && dacl_present && dacl) {
				wchar_t dir_mut[MAX_PATH];
				wcscpy(dir_mut, WSL_SHARED_DIR);
				set_sec(dir_mut, 1 /* SE_FILE_OBJECT */,
					DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
					NULL, NULL, dacl, NULL);
			}
			LocalFree(sd);
		}
	}
}

static void wsl_save_owner_cache(const struct wsl_host_info *info) {
	char sid_u8[256], dom_u8[256], usr_u8[256], dst_u8[256];
	char buf[1200];
	HANDLE h;
	DWORD written = 0;
	int n;
	if (!info->available || !info->owner_sid[0] || !info->owner_user[0]) return;
	wsl_ensure_shared_dir_acl(info->owner_sid);
	WideCharToMultiByte(CP_UTF8, 0, info->owner_sid, -1, sid_u8, sizeof(sid_u8), NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, info->owner_domain, -1, dom_u8, sizeof(dom_u8), NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, info->owner_user, -1, usr_u8, sizeof(usr_u8), NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, info->distro, -1, dst_u8, sizeof(dst_u8), NULL, NULL);
	n = snprintf(buf, sizeof(buf), "sid=%s\ndomain=%s\nuser=%s\ndistro=%s\nuid=%lu\n",
		sid_u8, dom_u8, usr_u8, dst_u8, (unsigned long)info->default_uid);
	if (n <= 0 || n >= (int)sizeof(buf)) return;
	h = CreateFileW(WSL_OWNER_CONF, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h != INVALID_HANDLE_VALUE) {
		WriteFile(h, buf, (DWORD)n, &written, NULL);
		CloseHandle(h);
	}
}

static int wsl_load_owner_cache(struct wsl_host_info *info) {
	HANDLE h = CreateFileW(WSL_OWNER_CONF, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	char buf[1200];
	DWORD nread = 0;
	char *line, *next;
	if (h == INVALID_HANDLE_VALUE) return 0;
	if (!ReadFile(h, buf, sizeof(buf) - 1, &nread, NULL) || nread == 0) {
		CloseHandle(h);
		return 0;
	}
	CloseHandle(h);
	buf[nread] = '\0';
	for (line = buf; line && *line; line = next) {
		char *eq;
		next = strchr(line, '\n');
		if (next) *next++ = '\0';
		{
			size_t l = strlen(line);
			while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == ' ')) line[--l] = '\0';
		}
		eq = strchr(line, '=');
		if (!eq) continue;
		*eq++ = '\0';
		if (!strcmp(line, "sid")) MultiByteToWideChar(CP_UTF8, 0, eq, -1, info->owner_sid, 128);
		else if (!strcmp(line, "domain")) MultiByteToWideChar(CP_UTF8, 0, eq, -1, info->owner_domain, 256);
		else if (!strcmp(line, "user")) MultiByteToWideChar(CP_UTF8, 0, eq, -1, info->owner_user, 256);
		else if (!strcmp(line, "distro")) MultiByteToWideChar(CP_UTF8, 0, eq, -1, info->distro, 128);
		else if (!strcmp(line, "uid")) info->default_uid = (DWORD)strtoul(eq, NULL, 10);
	}
	if (info->distro[0] && info->owner_user[0]) {
		info->available = 1;
		return 1;
	}
	return 0;
}

static int wsl_probe_host(struct wsl_host_info *info) {
	DWORD attrs;
	memset(info, 0, sizeof(*info));
	info->running_as_system = wsl_is_current_process_system();

	/* 1. Windows WSL executable must exist */
	attrs = GetFileAttributesW(L"C:\\Windows\\System32\\wsl.exe");
	if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY))
		return 0;

	/* 2. Check HKCU when running as a regular user */
	if (!info->running_as_system) {
		if (wsl_read_lxss_key(HKEY_CURRENT_USER,
				L"Software\\Microsoft\\Windows\\CurrentVersion\\Lxss",
				info->distro, 128, &info->default_uid)) {
			DWORD ulen = 256;
			GetUserNameW(info->owner_user, &ulen);
			info->available = 1;
			return 1;
		}
	}

	/* 3. Scan loaded HKEY_USERS hives (works as SYSTEM when any user profile is loaded) */
	{
		DWORD idx = 0;
		for (;; idx++) {
			wchar_t sid_name[128];
			DWORD sid_len = 128;
			wchar_t lxss_path[256];
			if (RegEnumKeyExW(HKEY_USERS, idx, sid_name, &sid_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
				break;
			if (wcsncmp(sid_name, L"S-1-5-21-", 9) != 0) continue;
			if (wcsstr(sid_name, L"_Classes") != NULL) continue;
			_snwprintf(lxss_path, 256, L"%ls\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss", sid_name);
			if (wsl_read_lxss_key(HKEY_USERS, lxss_path, info->distro, 128, &info->default_uid)) {
				wcsncpy(info->owner_sid, sid_name, 127);
				wsl_sid_string_to_account(sid_name, info->owner_domain, 256, info->owner_user, 256);
				info->available = 1;
				wsl_save_owner_cache(info);
				return 1;
			}
		}
	}

	/* 4. Cold-boot no-logon check: cached owner metadata first */
	if (wsl_load_owner_cache(info)) {
		return 1;
	}

	/* 5. Cold-boot fallback: inspect unloaded NTUSER.DAT hives via ProfileList (SYSTEM only) */
	if (info->running_as_system) {
		HKEY plist = NULL;
		wsl_enable_privilege(L"SeBackupPrivilege");
		wsl_enable_privilege(L"SeRestorePrivilege");
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
				L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
				0, KEY_READ, &plist) == ERROR_SUCCESS) {
			DWORD idx = 0;
			for (;; idx++) {
				wchar_t sid_name[128];
				DWORD sid_len = 128;
				HKEY pk = NULL;
				if (RegEnumKeyExW(plist, idx, sid_name, &sid_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
					break;
				if (wcsncmp(sid_name, L"S-1-5-21-", 9) != 0) continue;
				if (RegOpenKeyExW(plist, sid_name, 0, KEY_READ, &pk) == ERROR_SUCCESS) {
					wchar_t img[MAX_PATH] = {0}, ntuser[MAX_PATH];
					DWORD cb = sizeof(img), type = 0;
					if (RegQueryValueExW(pk, L"ProfileImagePath", NULL, &type, (LPBYTE)img, &cb) == ERROR_SUCCESS &&
							img[0]) {
						wchar_t expanded[MAX_PATH];
						if (type == REG_EXPAND_SZ && ExpandEnvironmentStringsW(img, expanded, MAX_PATH) > 0) {
							wcsncpy(img, expanded, MAX_PATH - 1);
						}
						_snwprintf(ntuser, MAX_PATH, L"%ls\\NTUSER.DAT", img);
						if (GetFileAttributesW(ntuser) != INVALID_FILE_ATTRIBUTES) {
							const wchar_t *tmp_hive = L"DropbearWslProbeTmp";
							if (RegLoadKeyW(HKEY_USERS, tmp_hive, ntuser) == ERROR_SUCCESS) {
								wchar_t lxss_path[256];
								int hit;
								_snwprintf(lxss_path, 256,
									L"%ls\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss", tmp_hive);
								hit = wsl_read_lxss_key(HKEY_USERS, lxss_path,
									info->distro, 128, &info->default_uid);
								RegUnLoadKeyW(HKEY_USERS, tmp_hive);
								if (hit) {
									wcsncpy(info->owner_sid, sid_name, 127);
									wsl_sid_string_to_account(sid_name, info->owner_domain, 256,
										info->owner_user, 256);
									info->available = 1;
									wsl_save_owner_cache(info);
									RegCloseKey(pk);
									RegCloseKey(plist);
									return 1;
								}
							}
						}
					}
					RegCloseKey(pk);
				}
			}
			RegCloseKey(plist);
		}
	}

	return 0;
}

int dropbear_win_wsl_is_available(void) {
	struct wsl_host_info info;
	if (!dropbear_win_wsl_has_embedded()) {
		wchar_t dummy[MAX_PATH];
		if (!wsl_resolve_executable(dummy, MAX_PATH)) return 0;
	}
	return wsl_probe_host(&info);
}

int dropbear_win_wsl_distro_utf8(char *out, size_t cap) {
	struct wsl_host_info info;
	if (!out || cap == 0) return 0;
	out[0] = '\0';
	if (!wsl_probe_host(&info) || !info.distro[0]) return 0;
	return WideCharToMultiByte(CP_UTF8, 0, info.distro, -1, out, (int)cap, NULL, NULL) > 0;
}

/* ---------------- Built-in DropbearWin WSL Bridge Supervisor ---------------- */

static HANDLE g_wsl_stop_event = NULL;
static HANDLE g_wsl_supervisor_thread = NULL;
static LONG g_wsl_supervisor_started = 0;

static void wsl_ensure_lxss_service(void) {
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	SC_HANDLE svc;
	SERVICE_STATUS ss;
	if (!scm) return;
	svc = OpenServiceW(scm, L"LxssManager", SERVICE_QUERY_STATUS | SERVICE_START);
	if (svc) {
		if (QueryServiceStatus(svc, &ss) && ss.dwCurrentState == SERVICE_STOPPED) {
			StartServiceW(svc, 0, NULL);
			Sleep(500);
		}
		CloseServiceHandle(svc);
	}
	CloseServiceHandle(scm);
}

static int wsl_broker_is_reachable(void) {
	HANDLE h = CreateFileW(WSL_BROKER_JSON, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	char buf[1024];
	DWORD nread = 0;
	char *p;
	int port = 0;
	SOCKET s;
	struct sockaddr_in addr;
	u_long nb = 1;
	int ok = 0;

	if (h == INVALID_HANDLE_VALUE) return 0;
	if (!ReadFile(h, buf, sizeof(buf) - 1, &nread, NULL) || nread == 0) {
		CloseHandle(h);
		return 0;
	}
	CloseHandle(h);
	buf[nread] = '\0';
	p = strstr(buf, "\"port\"");
	if (!p) return 0;
	p = strchr(p, ':');
	if (!p) return 0;
	port = atoi(p + 1);
	if (port <= 0 || port > 65535) return 0;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) return 0;
	ioctlsocket(s, FIONBIO, &nb);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons((u_short)port);
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		ok = 1;
	} else if (WSAGetLastError() == WSAEWOULDBLOCK) {
		fd_set wfds;
		struct timeval tv = {0, 300000};
		FD_ZERO(&wfds);
		FD_SET(s, &wfds);
		if (select(0, NULL, &wfds, NULL, &tv) > 0) {
			int err = 0, elen = sizeof(err);
			if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &elen) == 0 && err == 0)
				ok = 1;
		}
	}
	closesocket(s);
	return ok;
}

static HANDLE wsl_acquire_wts_token(const struct wsl_host_info *info) {
	typedef BOOL (WINAPI *enum_sessions_fn)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW *, DWORD *);
	typedef BOOL (WINAPI *query_session_fn)(HANDLE, DWORD, WTS_INFO_CLASS, LPWSTR *, DWORD *);
	typedef BOOL (WINAPI *query_user_token_fn)(ULONG, PHANDLE);
	typedef void (WINAPI *wts_free_fn)(PVOID);
	HMODULE wts = wsl_load_system_dll(L"wtsapi32.dll");
	enum_sessions_fn enum_sessions;
	query_session_fn query_session;
	query_user_token_fn query_user_token;
	wts_free_fn wts_free;
	PWTS_SESSION_INFOW sessions = NULL;
	DWORD count = 0, i, chosen = 0xffffffffUL, fallback = 0xffffffffUL;
	HANDLE tok = NULL;

	if (!wts) return NULL;
	enum_sessions = (enum_sessions_fn)(void *)GetProcAddress(wts, "WTSEnumerateSessionsW");
	query_session = (query_session_fn)(void *)GetProcAddress(wts, "WTSQuerySessionInformationW");
	query_user_token = (query_user_token_fn)(void *)GetProcAddress(wts, "WTSQueryUserToken");
	wts_free = (wts_free_fn)(void *)GetProcAddress(wts, "WTSFreeMemory");
	if (!enum_sessions || !query_session || !query_user_token || !wts_free) {
		FreeLibrary(wts);
		return NULL;
	}
	if (enum_sessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count) && sessions) {
		for (i = 0; i < count; i++) {
			LPWSTR uw = NULL;
			DWORD ub = 0;
			if (sessions[i].SessionId == 0) continue;
			if (!query_session(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId, WTSUserName, &uw, &ub) || !uw || !uw[0]) {
				if (uw) wts_free(uw);
				continue;
			}
			if (_wcsicmp(uw, info->owner_user) == 0) {
				if (sessions[i].State == WTSActive || sessions[i].State == WTSConnected) {
					chosen = sessions[i].SessionId;
					wts_free(uw);
					break;
				}
				if (fallback == 0xffffffffUL) fallback = sessions[i].SessionId;
			}
			wts_free(uw);
		}
		wts_free(sessions);
	}
	if (chosen == 0xffffffffUL) chosen = fallback;
	if (chosen != 0xffffffffUL) {
		query_user_token(chosen, &tok);
	}
	FreeLibrary(wts);
	return tok;
}

static HANDLE wsl_acquire_s4u_token(const struct wsl_host_info *info) {
	HMODULE sec = wsl_load_system_dll(L"secur32.dll");
	lsa_register_logon_fn reg_logon;
	lsa_connect_untrusted_fn conn_untrusted;
	lsa_lookup_pkg_fn lookup_pkg;
	lsa_logon_user_fn logon_user;
	lsa_free_buf_fn free_buf;
	lsa_deregister_fn dereg;
	HANDLE lsa = NULL, tok = NULL;
	ULONG mode = 0, pkg_id = 0, prof_len = 0;
	PVOID prof_buf = NULL;
	LUID logon_id;
	LONG sub_status = 0, st;
	unsigned char quota[128];
	WSL_LSA_STRING proc_name, pkg_name, origin_name;
	WSL_TOKEN_SOURCE src;
	size_t ubytes, dbytes, total_sz;
	WSL_MSV1_0_S4U_LOGON *s4u = NULL;
	wchar_t *uptr, *dptr;

	if (!sec || !info->owner_user[0]) {
		if (sec) FreeLibrary(sec);
		return NULL;
	}
	wsl_enable_privilege(L"SeTcbPrivilege");
	reg_logon = (lsa_register_logon_fn)(void *)GetProcAddress(sec, "LsaRegisterLogonProcess");
	conn_untrusted = (lsa_connect_untrusted_fn)(void *)GetProcAddress(sec, "LsaConnectUntrusted");
	lookup_pkg = (lsa_lookup_pkg_fn)(void *)GetProcAddress(sec, "LsaLookupAuthenticationPackage");
	logon_user = (lsa_logon_user_fn)(void *)GetProcAddress(sec, "LsaLogonUser");
	free_buf = (lsa_free_buf_fn)(void *)GetProcAddress(sec, "LsaFreeReturnBuffer");
	dereg = (lsa_deregister_fn)(void *)GetProcAddress(sec, "LsaDeregisterLogonProcess");
	if (!lookup_pkg || !logon_user || !free_buf || !dereg) {
		FreeLibrary(sec);
		return NULL;
	}

	proc_name.Buffer = "DropbearWslSupervisor";
	proc_name.Length = (USHORT)strlen(proc_name.Buffer);
	proc_name.MaximumLength = proc_name.Length + 1;

	st = reg_logon ? reg_logon(&proc_name, &lsa, &mode) : -1;
	if (st != 0 && conn_untrusted) st = conn_untrusted(&lsa);
	if (st != 0 || !lsa) {
		FreeLibrary(sec);
		return NULL;
	}

	pkg_name.Buffer = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
	pkg_name.Length = (USHORT)strlen(pkg_name.Buffer);
	pkg_name.MaximumLength = pkg_name.Length + 1;
	if (lookup_pkg(lsa, &pkg_name, &pkg_id) != 0) {
		dereg(lsa);
		FreeLibrary(sec);
		return NULL;
	}

	ubytes = wcslen(info->owner_user) * sizeof(wchar_t);
	dbytes = wcslen(info->owner_domain) * sizeof(wchar_t);
	total_sz = sizeof(WSL_MSV1_0_S4U_LOGON) + ubytes + dbytes + 4;
	s4u = (WSL_MSV1_0_S4U_LOGON *)calloc(1, total_sz);
	if (!s4u) {
		dereg(lsa);
		FreeLibrary(sec);
		return NULL;
	}
	uptr = (wchar_t *)(s4u + 1);
	memcpy(uptr, info->owner_user, ubytes);
	dptr = (wchar_t *)((unsigned char *)uptr + ubytes);
	if (dbytes > 0) memcpy(dptr, info->owner_domain, dbytes);

	s4u->MessageType = 12; /* MsV1_0S4ULogon */
	s4u->Flags = 0;
	s4u->UserPrincipalName.Length = (USHORT)ubytes;
	s4u->UserPrincipalName.MaximumLength = (USHORT)ubytes;
	s4u->UserPrincipalName.Buffer = uptr;
	s4u->DomainName.Length = (USHORT)dbytes;
	s4u->DomainName.MaximumLength = (USHORT)dbytes;
	s4u->DomainName.Buffer = dptr;

	origin_name.Buffer = "DropbearWin";
	origin_name.Length = (USHORT)strlen(origin_name.Buffer);
	origin_name.MaximumLength = origin_name.Length + 1;
	memset(&src, 0, sizeof(src));
	memcpy(src.SourceName, "DrpbrWsl", 8);
	AllocateLocallyUniqueId(&src.SourceIdentifier);
	memset(quota, 0, sizeof(quota));

	/* LogonType 4 = Batch (matches Task Scheduler S4U non-interactive logon) */
	st = logon_user(lsa, &origin_name, 4, pkg_id, s4u, (ULONG)total_sz, NULL, &src,
		&prof_buf, &prof_len, &logon_id, &tok, quota, &sub_status);
	if (prof_buf) free_buf(prof_buf);
	free(s4u);
	dereg(lsa);
	FreeLibrary(sec);
	if (st != 0) return NULL;
	return tok;
}

static HANDLE wsl_spawn_supervised_daemon(const wchar_t *wsl_exe, const struct wsl_host_info *info,
		HANDLE *out_profile_token, HANDLE *out_profile_handle, const char **out_mode) {
	wchar_t cmdline[1024];
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE nul_h;
	SECURITY_ATTRIBUTES sa;

	*out_profile_token = NULL;
	*out_profile_handle = NULL;
	*out_mode = "direct";

	_snwprintf(cmdline, 1024, L"\"%ls\" daemon --distro \"%ls\" --user auto", wsl_exe, info->distro);

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	nul_h = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdInput = nul_h;
	si.hStdOutput = nul_h;
	si.hStdError = nul_h;

	if (!info->running_as_system) {
		BOOL ok = CreateProcessW(wsl_exe, cmdline, NULL, NULL, TRUE,
			CREATE_NO_WINDOW | HIGH_PRIORITY_CLASS | CREATE_NEW_PROCESS_GROUP,
			NULL, NULL, &si, &pi);
		if (nul_h != INVALID_HANDLE_VALUE) CloseHandle(nul_h);
		if (!ok) return NULL;
		CloseHandle(pi.hThread);
		return pi.hProcess;
	}

	/* Running as NT AUTHORITY\SYSTEM: spawn in Session 0 under WSL owner's token */
	{
		typedef BOOL (WINAPI *create_env_fn)(LPVOID *, HANDLE, BOOL);
		typedef BOOL (WINAPI *destroy_env_fn)(LPVOID);
		typedef BOOL (WINAPI *load_prof_fn)(HANDLE, WSL_PROFILEINFOW *);
		HMODULE userenv = wsl_load_system_dll(L"userenv.dll");
		create_env_fn create_env = userenv ? (create_env_fn)(void *)GetProcAddress(userenv, "CreateEnvironmentBlock") : NULL;
		destroy_env_fn destroy_env = userenv ? (destroy_env_fn)(void *)GetProcAddress(userenv, "DestroyEnvironmentBlock") : NULL;
		load_prof_fn load_prof = userenv ? (load_prof_fn)(void *)GetProcAddress(userenv, "LoadUserProfileW") : NULL;
		HANDLE tok = NULL, prim = NULL;
		LPVOID env_block = NULL;
		DWORD zero_sess = 0;
		WSL_PROFILEINFOW prof;
		BOOL ok = FALSE;

		wsl_enable_privilege(L"SeAssignPrimaryTokenPrivilege");
		wsl_enable_privilege(L"SeIncreaseQuotaPrivilege");
		wsl_enable_privilege(L"SeImpersonatePrivilege");

		tok = wsl_acquire_wts_token(info);
		if (tok) {
			*out_mode = "WTS-Session0";
		} else {
			tok = wsl_acquire_s4u_token(info);
			if (tok) {
				*out_mode = "S4U-NoLogon";
				if (load_prof) {
					memset(&prof, 0, sizeof(prof));
					prof.dwSize = sizeof(prof);
					prof.dwFlags = 1; /* PI_NOUI */
					prof.lpUserName = (LPWSTR)info->owner_user;
					if (load_prof(tok, &prof)) {
						*out_profile_handle = prof.hProfile;
					}
				}
			}
		}

		if (tok) {
			if (DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &prim)) {
				SetTokenInformation(prim, TokenSessionId, &zero_sess, sizeof(zero_sess));
				if (create_env) create_env(&env_block, prim, FALSE);
				ok = CreateProcessAsUserW(prim, wsl_exe, cmdline, NULL, NULL, TRUE,
					CREATE_NO_WINDOW | HIGH_PRIORITY_CLASS | CREATE_NEW_PROCESS_GROUP |
					(env_block ? CREATE_UNICODE_ENVIRONMENT : 0),
					env_block, NULL, &si, &pi);
				if (env_block && destroy_env) destroy_env(env_block);
				CloseHandle(prim);
			}
			if (*out_profile_handle) {
				*out_profile_token = tok; /* keep alive for UnloadUserProfile on stop */
			} else {
				CloseHandle(tok);
			}
		}
		if (userenv) FreeLibrary(userenv);
		if (nul_h != INVALID_HANDLE_VALUE) CloseHandle(nul_h);
		if (!ok) {
			if (*out_profile_token) {
				CloseHandle(*out_profile_token);
				*out_profile_token = NULL;
				*out_profile_handle = NULL;
			}
			return NULL;
		}
		CloseHandle(pi.hThread);
		return pi.hProcess;
	}
}

static DWORD WINAPI wsl_supervisor_thread_proc(LPVOID param) {
	struct wsl_host_info info;
	wchar_t wsl_exe[MAX_PATH];
	DWORD shim_attrs;
	(void)param;

	if (!wsl_probe_host(&info)) {
		dropbear_win_logf("[wsl-bridge] auto-probe: no WSL distro found on this host; bridge inactive\r\n");
		return 0;
	}
	{
		char d_u8[128], u_u8[256];
		WideCharToMultiByte(CP_UTF8, 0, info.distro, -1, d_u8, sizeof(d_u8), NULL, NULL);
		WideCharToMultiByte(CP_UTF8, 0, info.owner_user, -1, u_u8, sizeof(u_u8), NULL, NULL);
		dropbear_win_logf("[wsl-bridge] auto-probe: detected WSL distro='%s' owner='%s'\r\n", d_u8, u_u8);
	}

	wsl_ensure_shared_dir_acl(info.owner_sid);
	wsl_ensure_lxss_service();

	if (!wsl_resolve_executable(wsl_exe, MAX_PATH)) {
		dropbear_win_logf("[wsl-bridge] could not resolve/extract embedded wsl-bridge.exe\r\n");
		return 0;
	}
	/* Keep system shims directory synchronized if present */
	shim_attrs = GetFileAttributesW(L"C:\\Program Files\\wsl-bridge");
	if (shim_attrs != INVALID_FILE_ATTRIBUTES && (shim_attrs & FILE_ATTRIBUTE_DIRECTORY)) {
		dropbear_win_wsl_extract_to_dir(L"C:\\Program Files\\wsl-bridge", 1);
	}

	while (WaitForSingleObject(g_wsl_stop_event, 0) == WAIT_TIMEOUT) {
		HANDLE child = NULL, prof_tok = NULL, prof_h = NULL;
		const char *mode = "direct";

		/* If another healthy broker is already alive, monitor it without fighting */
		if (wsl_broker_is_reachable()) {
			if (WaitForSingleObject(g_wsl_stop_event, 3000) != WAIT_TIMEOUT) break;
			continue;
		}

		child = wsl_spawn_supervised_daemon(wsl_exe, &info, &prof_tok, &prof_h, &mode);
		if (!child) {
			dropbear_win_logf("[wsl-bridge] failed to launch supervised daemon (mode=%s); retrying in 5s\r\n", mode);
			if (WaitForSingleObject(g_wsl_stop_event, 5000) != WAIT_TIMEOUT) break;
			continue;
		}
		dropbear_win_logf("[wsl-bridge] supervised daemon started (pid=%lu, mode=%s)\r\n",
			(unsigned long)GetProcessId(child), mode);

		{
			HANDLE waits[2] = { g_wsl_stop_event, child };
			DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
			if (w == WAIT_OBJECT_0) {
				/* DropbearWin is shutting down: stop our supervised daemon cleanly */
				TerminateProcess(child, 0);
				WaitForSingleObject(child, 2000);
				CloseHandle(child);
				if (prof_tok && prof_h) {
					typedef BOOL (WINAPI *unload_prof_fn)(HANDLE, HANDLE);
					HMODULE ue = wsl_load_system_dll(L"userenv.dll");
					unload_prof_fn ul = ue ? (unload_prof_fn)(void *)GetProcAddress(ue, "UnloadUserProfile") : NULL;
					if (ul) ul(prof_tok, prof_h);
					if (ue) FreeLibrary(ue);
					CloseHandle(prof_tok);
				}
				break;
			}
		}
		{
			DWORD code = 0;
			GetExitCodeProcess(child, &code);
			CloseHandle(child);
			dropbear_win_logf("[wsl-bridge] supervised daemon exited (rc=%lu); restarting in 2s\r\n", (unsigned long)code);
		}
		if (prof_tok && prof_h) {
			typedef BOOL (WINAPI *unload_prof_fn)(HANDLE, HANDLE);
			HMODULE ue = wsl_load_system_dll(L"userenv.dll");
			unload_prof_fn ul = ue ? (unload_prof_fn)(void *)GetProcAddress(ue, "UnloadUserProfile") : NULL;
			if (ul) ul(prof_tok, prof_h);
			if (ue) FreeLibrary(ue);
			CloseHandle(prof_tok);
		}
		if (WaitForSingleObject(g_wsl_stop_event, 2000) != WAIT_TIMEOUT) break;
	}
	return 0;
}

void dropbear_win_wsl_supervisor_start(void) {
	if (InterlockedCompareExchange(&g_wsl_supervisor_started, 1, 0) != 0) return;
	g_wsl_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!g_wsl_stop_event) return;
	g_wsl_supervisor_thread = CreateThread(NULL, 0, wsl_supervisor_thread_proc, NULL, 0, NULL);
}

void dropbear_win_wsl_supervisor_stop(void) {
	if (!g_wsl_stop_event) return;
	SetEvent(g_wsl_stop_event);
	if (g_wsl_supervisor_thread) {
		WaitForSingleObject(g_wsl_supervisor_thread, 4000);
		CloseHandle(g_wsl_supervisor_thread);
		g_wsl_supervisor_thread = NULL;
	}
	CloseHandle(g_wsl_stop_event);
	g_wsl_stop_event = NULL;
	InterlockedExchange(&g_wsl_supervisor_started, 0);
}

/* ---------------- CLI & SSH Pass-Through Dispatch ---------------- */

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
