/* Private staging for client-side script execution over SSH/SFTP. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include <sddl.h>

static int create_script_directory(const wchar_t *directory) {
	HANDLE token = NULL;
	TOKEN_USER *user = NULL;
	LPWSTR sid = NULL;
	PSECURITY_DESCRIPTOR descriptor = NULL;
	SECURITY_ATTRIBUTES security = {sizeof(security), NULL, FALSE};
	wchar_t acl[256];
	DWORD size = 0, error = ERROR_ACCESS_DENIED;
	int created = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
	GetTokenInformation(token, TokenUser, NULL, 0, &size);
	if (!size) goto done;
	user = malloc(size);
	if (!user || !GetTokenInformation(token, TokenUser, user, size, &size) ||
			!ConvertSidToStringSidW(user->User.Sid, &sid)) goto done;
	if (_snwprintf(acl, sizeof(acl) / sizeof(acl[0]),
			L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%ls)", sid) <= 0 ||
			!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl,
				SDDL_REVISION_1, &descriptor, NULL)) goto done;
	security.lpSecurityDescriptor = descriptor;
	/* Never reuse an existing path, including a junction created by another process. */
	created = CreateDirectoryW(directory, &security);
	if (!created) error = GetLastError();
done:
	if (descriptor) LocalFree(descriptor);
	if (sid) LocalFree(sid);
	free(user);
	if (token) CloseHandle(token);
	if (!created) SetLastError(error);
	return created;
}

int dropbear_win_script_directory(const char *id, int create, char *output, size_t size) {
	static const wchar_t *const names[] = {L"script.ps1", L"script.py", L"script.js"};
	wchar_t temporary[MAX_PATH], directory[MAX_PATH], file[MAX_PATH];
	DWORD length, attributes;
	size_t i;
	int written;
	if (strlen(id) != 32 || strspn(id, "0123456789abcdef") != 32) {
		fputs("Script staging requires a 32-character lowercase hex ID.\n", stderr);
		return 2;
	}
	length = GetTempPathW(MAX_PATH, temporary);
	if (!length || length >= MAX_PATH) goto failure;
	written = _snwprintf(directory, MAX_PATH, L"%lsdropbear-script-%hs", temporary, id);
	if (written <= 0 || written + 12 >= MAX_PATH) {
		SetLastError(ERROR_FILENAME_EXCED_RANGE);
		goto failure;
	}
	if (!WideCharToMultiByte(CP_UTF8, 0, directory, -1, output, (int)size, NULL, NULL))
		goto failure;
	if (create) {
		if (!create_script_directory(directory)) goto failure;
		return 0;
	}
	attributes = GetFileAttributesW(directory);
	if (attributes == INVALID_FILE_ATTRIBUTES &&
			(GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND)) return 0;
	if (attributes == INVALID_FILE_ATTRIBUTES) goto failure;
	if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		SetLastError(ERROR_ACCESS_DENIED);
		goto failure;
	}
	/* Only uploaded scripts belong to this operation. Preserve any other files. */
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		_snwprintf(file, MAX_PATH, L"%ls\\%ls", directory, names[i]);
		attributes = GetFileAttributesW(file);
		if (attributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND) continue;
		if (attributes == INVALID_FILE_ATTRIBUTES) goto failure;
		if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
			SetLastError(ERROR_ACCESS_DENIED);
			goto failure;
		}
		if (!DeleteFileW(file)) goto failure;
	}
	if (!RemoveDirectoryW(directory)) goto failure;
	return 0;
failure:
	fprintf(stderr, "Script %s failed: Windows error %lu.\n", create ? "staging" : "cleanup",
		(unsigned long)GetLastError());
	return 1;
}
#endif
