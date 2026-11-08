/* Embedded client resources; no Python or external resource files at runtime. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include "win-account.h"
#include "win-agent-bundle.h"

struct bundle_file {
    const wchar_t *wide_name;
    const char *name, *data;
    size_t length;
};
#include "agent-bundle.generated.h"
#define BUNDLE_COUNT (sizeof(bundle_files) / sizeof(bundle_files[0]))

struct bundle_entry {
    wchar_t target[MAX_PATH], staged[MAX_PATH], backup[MAX_PATH];
    int saved, replaced;
};
struct dropbear_win_bundle_transaction { struct bundle_entry files[BUNDLE_COUNT]; };

const char *dropbear_win_bundle_content(const char *name) {
    unsigned int i;
    for (i = 0; i < BUNDLE_COUNT; i++)
        if (!strcmp(bundle_files[i].name, name)) return bundle_files[i].data;
    return NULL;
}

const wchar_t *dropbear_win_bundle_name(unsigned int index) {
    return index < BUNDLE_COUNT ? bundle_files[index].wide_name : NULL;
}

int dropbear_win_bundle_finish(struct dropbear_win_bundle_transaction *transaction, int commit) {
    unsigned int i;
    int ok = 1;
    if (!transaction) return 1;
    for (i = 0; i < BUNDLE_COUNT; i++) {
        struct bundle_entry *entry = &transaction->files[i];
        if (!commit && entry->replaced) {
            if (entry->saved) {
                if (!MoveFileExW(entry->backup, entry->target, MOVEFILE_REPLACE_EXISTING)) {
                    /* Keep the backup for recovery when rollback itself fails. */
                    fprintf(stderr, "Could not restore agent resource: %ls (backup: %ls).\n",
                        entry->target, entry->backup);
                    ok = 0;
                    continue;
                }
            } else if (!DeleteFileW(entry->target)) ok = 0;
        }
        if (entry->saved) {
            /* CopyFile preserves read-only attributes; backups are our own files. */
            SetFileAttributesW(entry->backup, FILE_ATTRIBUTE_NORMAL);
            if (!DeleteFileW(entry->backup) && GetLastError() != ERROR_FILE_NOT_FOUND) ok = 0;
        }
        if (*entry->staged) DeleteFileW(entry->staged);
    }
    free(transaction);
    return ok;
}

int dropbear_win_bundle_begin(const wchar_t *directory,
        struct dropbear_win_bundle_transaction **transaction) {
    struct dropbear_win_bundle_transaction *state = calloc(1, sizeof(*state));
    unsigned int i;
    DWORD attributes;
    *transaction = NULL;
    if (!state) return 0;
    attributes = GetFileAttributesW(directory);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) goto fail;
    /* Stage all bytes and backups first. Never trust an on-disk manifest as a deletion list. */
    for (i = 0; i < BUNDLE_COUNT; i++) {
        struct bundle_entry *entry = &state->files[i];
        HANDLE file;
        DWORD written;
        int n = _snwprintf(entry->target, MAX_PATH, L"%ls\\%ls", directory, bundle_files[i].wide_name);
        if (n <= 0 || n >= MAX_PATH) goto fail;
        n = _snwprintf(entry->staged, MAX_PATH, L"%ls.bundle-new-%lu", entry->target,
            (unsigned long)GetCurrentProcessId());
        if (n <= 0 || n >= MAX_PATH) { *entry->staged = 0; goto fail; }
        n = _snwprintf(entry->backup, MAX_PATH, L"%ls.bundle-old-%lu", entry->target,
            (unsigned long)GetCurrentProcessId());
        if (n <= 0 || n >= MAX_PATH) goto fail;
        file = CreateFileW(entry->staged, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) { *entry->staged = 0; goto fail; }
        if (!WriteFile(file, bundle_files[i].data, (DWORD)bundle_files[i].length, &written, NULL) ||
                written != bundle_files[i].length || !FlushFileBuffers(file)) {
            CloseHandle(file); goto fail;
        }
        if (!CloseHandle(file)) goto fail;
        attributes = GetFileAttributesW(entry->target);
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            if (attributes & FILE_ATTRIBUTE_DIRECTORY || !CopyFileW(entry->target, entry->backup, TRUE)) goto fail;
            entry->saved = 1;
        } else if (GetLastError() != ERROR_FILE_NOT_FOUND) goto fail;
    }
    for (i = 0; i < BUNDLE_COUNT; i++) {
        struct bundle_entry *entry = &state->files[i];
        if (!MoveFileExW(entry->staged, entry->target, MOVEFILE_REPLACE_EXISTING)) goto fail;
        entry->replaced = 1;
    }
    *transaction = state;
    return 1;
fail:
    fputs("Could not install embedded agent files; rolling back resource changes.\n", stderr);
    dropbear_win_bundle_finish(state, 0);
    return 0;
}

/* Installed snapshots live beside the EXE. Portable discovery keeps its data directory. */
int dropbear_win_bundle_directory(wchar_t *directory, size_t size) {
    wchar_t executable[MAX_PATH], marker[MAX_PATH], *slash;
    DWORD length = GetModuleFileNameW(NULL, executable, MAX_PATH), attributes;
    int n;
    if (!length || length >= MAX_PATH || !(slash = wcsrchr(executable, L'\\'))) return 0;
    *slash = 0;
    n = _snwprintf(marker, MAX_PATH, L"%ls\\dropbear-win.installed", executable);
    if (n <= 0 || n >= MAX_PATH) return 0;
    attributes = GetFileAttributesW(marker);
    if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        if (wcslen(executable) >= size) return 0;
        wcscpy(directory, executable);
        return 1;
    }
    return MultiByteToWideChar(CP_ACP, 0, dropbear_win_data_dir(), -1, directory, (int)size) != 0;
}

int dropbear_win_bundle_directory_utf8(char *directory, size_t size) {
    wchar_t wide[MAX_PATH];
    if (!dropbear_win_bundle_directory(wide, MAX_PATH)) return 0;
    return WideCharToMultiByte(CP_UTF8, 0, wide, -1, directory, (int)size, NULL, NULL) != 0;
}

int dropbear_win_bundle_export(const char *directory) {
    wchar_t wide[MAX_PATH];
    struct dropbear_win_bundle_transaction *state;
    if (!MultiByteToWideChar(CP_ACP, 0, directory, -1, wide, MAX_PATH) ||
            !dropbear_win_bundle_begin(wide, &state)) return 1;
    return dropbear_win_bundle_finish(state, 1) ? 0 : 1;
}
#endif
