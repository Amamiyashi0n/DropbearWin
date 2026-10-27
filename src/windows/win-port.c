/* Exclusive Windows listeners and explicit default-port replacement. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include <iphlpapi.h>
#include <tlhelp32.h>
#include "win32-compat.h"

int dropbear_win_takeover_enabled;
static HANDLE startup_mutex;
int dropbear_win_startup_lock(void) {
	DWORD result;
	if (startup_mutex) return 1;
	startup_mutex = CreateMutexW(NULL, FALSE, L"Global\\DropbearWin-start-52222");
	if (!startup_mutex) return 0;
	result = WaitForSingleObject(startup_mutex, 15000);
	if (result == WAIT_OBJECT_0 || result == WAIT_ABANDONED) return 1;
	CloseHandle(startup_mutex); startup_mutex = NULL;
	return 0;
}
void dropbear_win_startup_unlock(void) {
	if (!startup_mutex) return;
	ReleaseMutex(startup_mutex);
	CloseHandle(startup_mutex); startup_mutex = NULL;
}
typedef DWORD (WINAPI *tcp_table_fn)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);

/* Also reclaim older deployments which predate the listener watcher. Keep
 * actual handles, and validate child creation time against its parent so a
 * stale/reused parent PID does not include an unrelated older process. */
static int stop_owner_tree(HANDLE root, DWORD root_pid) {
	struct child_record { DWORD pid; HANDLE handle; FILETIME created; } *children;
	PROCESSENTRY32 entry;
	HANDLE snapshot;
	FILETIME unused1, unused2, unused3;
	unsigned int count = 1, index, parent, pass, before;
	int result;
	children = calloc(1024, sizeof(*children));
	if (!children) return 0;
	children[0].pid = root_pid; children[0].handle = root;
	if (!GetProcessTimes(root, &children[0].created, &unused1, &unused2, &unused3)) {
		free(children); return 0;
	}
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) { free(children); return 0; }
	for (pass = 0; pass < 32 && count < 1024; pass++) {
		before = count;
		entry.dwSize = sizeof(entry);
		if (!Process32First(snapshot, &entry)) break;
		do {
			if (entry.th32ProcessID == GetCurrentProcessId()) continue;
			for (index = 0; index < count && children[index].pid != entry.th32ProcessID; index++) { }
			if (index != count) continue;
			for (parent = 0; parent < count && children[parent].pid != entry.th32ParentProcessID; parent++) { }
			if (parent == count) continue;
			children[count].handle = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
				FALSE, entry.th32ProcessID);
			if (!children[count].handle) continue;
			if (!GetProcessTimes(children[count].handle, &children[count].created, &unused1, &unused2, &unused3) ||
				CompareFileTime(&children[count].created, &children[parent].created) < 0) {
				CloseHandle(children[count].handle); continue;
			}
			children[count++].pid = entry.th32ProcessID;
		} while (count < 1024 && Process32Next(snapshot, &entry));
		if (before == count) break;
	}
	CloseHandle(snapshot);
	result = TerminateProcess(root, 0) && WaitForSingleObject(root, 5000) == WAIT_OBJECT_0;
	if (result) {
		for (index = count; index-- > 1;) {
			if (WaitForSingleObject(children[index].handle, 0) != WAIT_OBJECT_0)
				TerminateProcess(children[index].handle, 0);
			if (WaitForSingleObject(children[index].handle, 3000) != WAIT_OBJECT_0) result = 0;
		}
	}
	for (index = 1; index < count; index++) CloseHandle(children[index].handle);
	free(children);
	return result;
}

static int stop_port_owners(tcp_table_fn query, ULONG family) {
	DWORD size = 0, result, count, index;
	void *table = NULL;
	int stopped = 0, attempt;
	for (attempt = 0; attempt < 4; attempt++) {
		result = query(table, &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
		if (result != ERROR_INSUFFICIENT_BUFFER) break;
		free(table);
		table = malloc(size);
		if (!table) return -1;
	}
	if (result != NO_ERROR || !table) { free(table); return -1; }
	count = *(DWORD *)table;
	for (index = 0; index < count; index++) {
		DWORD pid, port;
		HANDLE process;
		if (family == AF_INET) {
			MIB_TCPROW_OWNER_PID *row = &((MIB_TCPTABLE_OWNER_PID *)table)->table[index];
			pid = row->dwOwningPid; port = row->dwLocalPort;
		} else {
			MIB_TCP6ROW_OWNER_PID *row = &((MIB_TCP6TABLE_OWNER_PID *)table)->table[index];
			pid = row->dwOwningPid; port = row->dwLocalPort;
		}
		if (ntohs((u_short)port) != 52222 || !pid || pid == GetCurrentProcessId()) continue;
		process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!process) {
			fprintf(stderr, "Port 52222 takeover: opening PID %lu failed (Windows %lu)\n",
				(unsigned long)pid, (unsigned long)GetLastError());
			continue;
		}
		if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) { CloseHandle(process); continue; }
		fprintf(stderr, "Port 52222 takeover: terminating listening PID %lu\n", (unsigned long)pid);
		if (stop_owner_tree(process, pid))
			stopped++;
		else fprintf(stderr, "Port 52222 takeover: PID %lu did not stop (Windows %lu)\n",
			(unsigned long)pid, (unsigned long)GetLastError());
		CloseHandle(process);
	}
	free(table);
	return stopped;
}

int dropbear_win_bind_listener(int fd, const struct sockaddr *address, int length) {
	unsigned short port = address->sa_family == AF_INET
		? ntohs(((const struct sockaddr_in *)address)->sin_port)
		: address->sa_family == AF_INET6 ? ntohs(((const struct sockaddr_in6 *)address)->sin6_port) : 0;
	HMODULE library;
	tcp_table_fn query;
	int stopped = 0, attempt, original_error;
	wchar_t path[MAX_PATH];
	UINT used;
	if (dropbear_win_bind(fd, address, length) == 0) return 0;
	original_error = errno;
	if (!dropbear_win_takeover_enabled || port != 52222 ||
		(original_error != EADDRINUSE && original_error != EACCES)) return -1;
	/* Load the system library explicitly, without a new static DLL dependency. */
	used = GetSystemDirectoryW(path, MAX_PATH);
	if (!used || used + 14 >= MAX_PATH) return -1;
	wcscat(path, L"\\iphlpapi.dll");
	library = LoadLibraryW(path);
	if (!library) return -1;
	query = (tcp_table_fn)(void *)GetProcAddress(library, "GetExtendedTcpTable");
	if (query) {
		int ipv4 = stop_port_owners(query, AF_INET);
		int ipv6 = stop_port_owners(query, AF_INET6);
		stopped = (ipv4 > 0 ? ipv4 : 0) + (ipv6 > 0 ? ipv6 : 0);
	}
	FreeLibrary(library);
	if (!stopped) { errno = original_error; return -1; }
	/* Old connection processes can briefly retain accepted sockets while their
	 * listener watcher shuts them down. Never fall back to a shared bind. */
	for (attempt = 0; attempt < 100; attempt++) {
		if (dropbear_win_bind(fd, address, length) == 0) return 0;
		if (errno != EADDRINUSE && errno != EACCES) break;
		Sleep(50);
	}
	fprintf(stderr, "Port 52222 takeover: exclusive bind failed after cleanup\n");
	return -1;
}
#endif
