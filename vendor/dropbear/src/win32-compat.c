#define DROPBEAR_WIN32_COMPAT_IMPL
#include "includes.h"

#define WIN_FD_BASE 64
#define WIN_FD_COUNT 512

static SOCKET sockets[WIN_FD_COUNT];
static CRITICAL_SECTION socket_lock;
static dropbear_win_once socket_once = DROPBEAR_WIN_ONCE_INIT;

int dropbear_win_once_run(dropbear_win_once *once,
		dropbear_win_once_initializer initializer) {
	LONG state = InterlockedCompareExchange(&once->state, 1, 0);
	if (state == 0) {
		int initialized = initializer();
		InterlockedExchange(&once->state, initialized ? 2 : 3);
		return initialized;
	}
	while (state == 1) {
		Sleep(0);
		state = InterlockedCompareExchange(&once->state, 1, 1);
	}
	return state == 2;
}

static int init_socket_table(void) {
	WSADATA data;
	unsigned int i;
	InitializeCriticalSection(&socket_lock);
	for (i = 0; i < WIN_FD_COUNT; i++) sockets[i] = INVALID_SOCKET;
	return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

static int ensure_started(void) {
	return dropbear_win_once_run(&socket_once, init_socket_table);
}

static void set_errno_from_wsa(void) {
	switch (WSAGetLastError()) {
		case WSAEINTR: errno = EINTR; break;
		/* MinGW gives EWOULDBLOCK and EAGAIN different values. Dropbear's
		 * packet/channel retry paths use EAGAIN for nonblocking backpressure. */
		case WSAEWOULDBLOCK: errno = EAGAIN; break;
		case WSAEINPROGRESS: errno = EINPROGRESS; break;
		case WSAEADDRINUSE: errno = EADDRINUSE; break;
		case WSAEACCES: errno = EACCES; break;
		case WSAEADDRNOTAVAIL: errno = EADDRNOTAVAIL; break;
		case WSAECONNRESET: errno = ECONNRESET; break;
		case WSAECONNREFUSED: errno = ECONNREFUSED; break;
		case WSAETIMEDOUT: errno = ETIMEDOUT; break;
		case WSAENOTSOCK: errno = ENOTSOCK; break;
		default: errno = EIO; break;
	}
}

static int store_socket(SOCKET sock) {
	unsigned int i;
	int result = -1;
	/* Only explicitly duplicated sockets cross a process boundary. Inheriting
	 * unrelated listener/auth/bridge sockets prevents EOF and port release. */
	if (!SetHandleInformation((HANDLE)sock, HANDLE_FLAG_INHERIT, 0)) {
		errno = EIO;
		return -1;
	}
	if (!ensure_started()) {
		errno = ENETDOWN;
		return -1;
	}
	EnterCriticalSection(&socket_lock);
	for (i = 0; i < WIN_FD_COUNT; i++) {
		if (sockets[i] == INVALID_SOCKET) {
			sockets[i] = sock;
			result = (int)i + WIN_FD_BASE;
			break;
		}
	}
	LeaveCriticalSection(&socket_lock);
	if (result < 0) errno = EMFILE;
	return result;
}

static SOCKET lookup_socket(int fd) {
	SOCKET result = INVALID_SOCKET;
	int index = fd - WIN_FD_BASE;
	if (index < 0 || index >= WIN_FD_COUNT) return INVALID_SOCKET;
	if (!ensure_started()) return INVALID_SOCKET;
	EnterCriticalSection(&socket_lock);
	result = sockets[index];
	LeaveCriticalSection(&socket_lock);
	return result;
}

static SOCKET remove_socket(int fd) {
	SOCKET result = INVALID_SOCKET;
	int index = fd - WIN_FD_BASE;
	if (index < 0 || index >= WIN_FD_COUNT) return INVALID_SOCKET;
	if (!ensure_started()) return INVALID_SOCKET;
	EnterCriticalSection(&socket_lock);
	result = sockets[index];
	sockets[index] = INVALID_SOCKET;
	LeaveCriticalSection(&socket_lock);
	return result;
}

int dropbear_win_startup(void) {
	return ensure_started() ? 0 : -1;
}

int dropbear_win_socket(int af, int type, int protocol) {
	SOCKET sock;
	int fd;
	if (!ensure_started()) {
		errno = ENETDOWN;
		return -1;
	}
	sock = WSASocketW(af, type, protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (sock == INVALID_SOCKET) {
		set_errno_from_wsa();
		return -1;
	}
	fd = store_socket(sock);
	if (fd < 0) closesocket(sock);
	return fd;
}

int dropbear_win_accept(int fd, struct sockaddr *addr, int *addrlen) {
	SOCKET sock = accept(lookup_socket(fd), addr, addrlen);
	int child;
	if (sock == INVALID_SOCKET) {
		set_errno_from_wsa();
		return -1;
	}
	child = store_socket(sock);
	if (child < 0) closesocket(sock);
	return child;
}

int dropbear_win_bind(int fd, const struct sockaddr *addr, int addrlen) {
	int ret = bind(lookup_socket(fd), addr, addrlen);
	if (ret == SOCKET_ERROR) set_errno_from_wsa();
	return ret == SOCKET_ERROR ? -1 : ret;
}

int dropbear_win_listen(int fd, int backlog) {
	int ret = listen(lookup_socket(fd), backlog);
	if (ret == SOCKET_ERROR) set_errno_from_wsa();
	return ret == SOCKET_ERROR ? -1 : ret;
}

int dropbear_win_connect(int fd, const struct sockaddr *addr, int addrlen) {
	int ret = connect(lookup_socket(fd), addr, addrlen);
	if (ret == SOCKET_ERROR) set_errno_from_wsa();
	return ret == SOCKET_ERROR ? -1 : ret;
}

static void translate_fdset(fd_set *source, fd_set *native_set) {
	u_int i;
	FD_ZERO(native_set);
	if (!source) return;
	for (i = 0; i < source->fd_count; i++) {
		SOCKET sock = lookup_socket((int)source->fd_array[i]);
		if (sock != INVALID_SOCKET) FD_SET(sock, native_set);
	}
}

static void filter_fdset(fd_set *source, const fd_set *native_set) {
	fd_set ready;
	u_int i;
	FD_ZERO(&ready);
	if (!source) return;
	for (i = 0; i < source->fd_count; i++) {
		int fd = (int)source->fd_array[i];
		SOCKET sock = lookup_socket(fd);
		if (sock != INVALID_SOCKET && FD_ISSET(sock, native_set)) {
			FD_SET((SOCKET)fd, &ready);
		}
	}
	*source = ready;
}

int dropbear_win_select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, const struct timeval *timeout) {
	fd_set native_read, native_write, native_except;
	int ret;
	(void)nfds;
	translate_fdset(readfds, &native_read);
	translate_fdset(writefds, &native_write);
	translate_fdset(exceptfds, &native_except);
	ret = select(0, readfds ? &native_read : NULL,
		writefds ? &native_write : NULL,
		exceptfds ? &native_except : NULL, timeout);
	if (ret == SOCKET_ERROR) {
		set_errno_from_wsa();
		return -1;
	}
	filter_fdset(readfds, &native_read);
	filter_fdset(writefds, &native_write);
	filter_fdset(exceptfds, &native_except);
	return ret;
}

int dropbear_win_setsockopt(int fd, int level, int optname,
		const void *optval, int optlen) {
	int ret = setsockopt(lookup_socket(fd), level, optname, (const char *)optval, optlen);
	if (ret == SOCKET_ERROR) set_errno_from_wsa();
	return ret == SOCKET_ERROR ? -1 : ret;
}

int dropbear_win_getsockopt(int fd, int level, int optname,
		void *optval, int *optlen) {
	int ret = getsockopt(lookup_socket(fd), level, optname, (char *)optval, optlen);
	if (ret == SOCKET_ERROR) set_errno_from_wsa();
	return ret == SOCKET_ERROR ? -1 : ret;
}

int dropbear_win_getsockname(int fd, struct sockaddr *addr, int *addrlen) {
	int ret = getsockname(lookup_socket(fd), addr, addrlen);
	if (ret == SOCKET_ERROR) set_errno_from_wsa();
	return ret == SOCKET_ERROR ? -1 : ret;
}

int dropbear_win_getpeername(int fd, struct sockaddr *addr, int *addrlen) {
	int ret = getpeername(lookup_socket(fd), addr, addrlen);
	if (ret == SOCKET_ERROR) set_errno_from_wsa();
	return ret == SOCKET_ERROR ? -1 : ret;
}

int dropbear_win_shutdown(int fd, int how) {
	int ret = shutdown(lookup_socket(fd), how);
	if (ret == SOCKET_ERROR) set_errno_from_wsa();
	return ret == SOCKET_ERROR ? -1 : ret;
}

int dropbear_win_socketpair(int fds[2]) {
	SOCKET listener = INVALID_SOCKET, left = INVALID_SOCKET, right = INVALID_SOCKET;
	struct sockaddr_in addr;
	int addrlen = sizeof(addr);
	int first = -1, second = -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	listener = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	if (listener == INVALID_SOCKET || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) ||
		listen(listener, 1) || getsockname(listener, (struct sockaddr *)&addr, &addrlen)) goto fail;
	left = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	if (left == INVALID_SOCKET || connect(left, (struct sockaddr *)&addr, sizeof(addr))) goto fail;
	right = accept(listener, NULL, NULL);
	if (right == INVALID_SOCKET) goto fail;
	closesocket(listener);
	listener = INVALID_SOCKET;
	first = store_socket(left);
	if (first < 0) goto fail;
	left = INVALID_SOCKET;
	second = store_socket(right);
	if (second < 0) goto fail;
	right = INVALID_SOCKET;
	fds[0] = first;
	fds[1] = second;
	return 0;

fail:
	set_errno_from_wsa();
	if (listener != INVALID_SOCKET) closesocket(listener);
	if (left != INVALID_SOCKET) closesocket(left);
	if (right != INVALID_SOCKET) closesocket(right);
	if (first >= 0) dropbear_win_close(first);
	return -1;
}

int dropbear_win_export_socket(int fd, DWORD target_pid, WSAPROTOCOL_INFOW *info) {
	if (WSADuplicateSocketW(lookup_socket(fd), target_pid, info) != 0) {
		set_errno_from_wsa();
		return -1;
	}
	return 0;
}

int dropbear_win_import_socket(const WSAPROTOCOL_INFOW *info) {
	SOCKET sock = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
		FROM_PROTOCOL_INFO, (LPWSAPROTOCOL_INFOW)info, 0, WSA_FLAG_OVERLAPPED);
	int fd;
	if (sock == INVALID_SOCKET) {
		set_errno_from_wsa();
		return -1;
	}
	fd = store_socket(sock);
	if (fd < 0) closesocket(sock);
	return fd;
}

ssize_t dropbear_win_read(int fd, void *buf, size_t count) {
	SOCKET sock = lookup_socket(fd);
	int ret;
	unsigned int requested = count > INT_MAX ? INT_MAX : (unsigned int)count;
	if (sock == INVALID_SOCKET) return _read(fd, buf, requested);
	ret = recv(sock, (char *)buf, (int)requested, 0);
	if (ret == SOCKET_ERROR) {
		set_errno_from_wsa();
		return -1;
	}
	return ret;
}

ssize_t dropbear_win_write(int fd, const void *buf, size_t count) {
	SOCKET sock = lookup_socket(fd);
	int ret;
	unsigned int requested = count > INT_MAX ? INT_MAX : (unsigned int)count;
	if (sock == INVALID_SOCKET) return _write(fd, buf, requested);
	ret = send(sock, (const char *)buf, (int)requested, 0);
	if (ret == SOCKET_ERROR) {
		set_errno_from_wsa();
		return -1;
	}
	return ret;
}

int dropbear_win_close(int fd) {
	SOCKET sock = remove_socket(fd);
	if (sock == INVALID_SOCKET) return _close(fd);
	if (closesocket(sock) == SOCKET_ERROR) {
		set_errno_from_wsa();
		return -1;
	}
	return 0;
}

int dropbear_win_fcntl(int fd, int cmd, ...) {
	SOCKET sock = lookup_socket(fd);
	va_list args;
	long value = 0;
	if (cmd == F_SETFL || cmd == F_SETFD) {
		va_start(args, cmd);
		value = va_arg(args, int);
		va_end(args);
	}
	if (sock == INVALID_SOCKET) return 0;
	if (cmd == F_GETFL) return 0;
	if (cmd == F_SETFL && (value & O_NONBLOCK)) {
		u_long enabled = 1;
		if (ioctlsocket(sock, FIONBIO, &enabled) == SOCKET_ERROR) {
			set_errno_from_wsa();
			return -1;
		}
	}
	return 0;
}

int dropbear_win_pipe(int fds[2]) { return dropbear_win_socketpair(fds); }

static wchar_t *utf8_path_to_wide(const char *path) {
	int length;
	wchar_t *wide;
	if (!path) {
		errno = EINVAL;
		return NULL;
	}
	length = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
	if (length <= 0) {
		errno = EINVAL;
		return NULL;
	}
	wide = HeapAlloc(GetProcessHeap(), 0, length * sizeof(*wide));
	if (!wide) {
		errno = ENOMEM;
		return NULL;
	}
	if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wide, length)) {
		HeapFree(GetProcessHeap(), 0, wide);
		errno = EINVAL;
		return NULL;
	}
	return wide;
}

int dropbear_win_open(const char *path, int flags, ...) {
	int mode = 0;
	if (flags & _O_CREAT) {
		va_list args;
		va_start(args, flags);
		mode = va_arg(args, int);
		va_end(args);
	}
	return _open(path, flags | _O_BINARY, mode);
}

int dropbear_win_utf8_open(const char *path, int flags, ...) {
	wchar_t *wide = utf8_path_to_wide(path);
	int mode = 0;
	int result;
	if (!wide) return -1;
	if (flags & _O_CREAT) {
		va_list args;
		va_start(args, flags);
		mode = va_arg(args, int);
		va_end(args);
	}
	result = _wopen(wide, flags | _O_BINARY, mode);
	HeapFree(GetProcessHeap(), 0, wide);
	return result;
}

int dropbear_win_utf8_stat(const char *path, struct _stat64 *status) {
	wchar_t *wide = utf8_path_to_wide(path);
	int result;
	if (!wide) return -1;
	result = _wstat64(wide, status);
	HeapFree(GetProcessHeap(), 0, wide);
	return result;
}

int dropbear_win_utf8_chmod(const char *path, int mode) {
	wchar_t *wide = utf8_path_to_wide(path);
	int result;
	if (!wide) return -1;
	result = _wchmod(wide, mode);
	HeapFree(GetProcessHeap(), 0, wide);
	return result;
}

int dropbear_win_utf8_mkdir(const char *path, int mode) {
	wchar_t *wide = utf8_path_to_wide(path);
	int result;
	(void)mode;
	if (!wide) return -1;
	result = _wmkdir(wide);
	HeapFree(GetProcessHeap(), 0, wide);
	return result;
}

int dropbear_win_utf8_utimes(const char *path, const struct timeval times[2]) {
	struct __utimbuf64 values;
	wchar_t *wide = utf8_path_to_wide(path);
	int result;
	if (!wide) return -1;
	if (times) {
		values.actime = times[0].tv_sec;
		values.modtime = times[1].tv_sec;
		result = _wutime64(wide, &values);
	} else {
		result = _wutime64(wide, NULL);
	}
	HeapFree(GetProcessHeap(), 0, wide);
	return result;
}

struct dropbear_win_utf8_dirent {
	long d_ino;
	unsigned short d_reclen;
	unsigned short d_namlen;
	char d_name[1024];
};

struct dropbear_win_utf8_dir {
	HANDLE find;
	WIN32_FIND_DATAW data;
	int first;
	struct dropbear_win_utf8_dirent entry;
};

static void set_errno_from_find_error(DWORD error) {
	switch (error) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
		case ERROR_NO_MORE_FILES:
			errno = ENOENT;
			break;
		case ERROR_ACCESS_DENIED:
		case ERROR_SHARING_VIOLATION:
			errno = EACCES;
			break;
		default:
			errno = EIO;
			break;
	}
}

DIR *dropbear_win_utf8_opendir(const char *path) {
	struct dropbear_win_utf8_dir *directory;
	wchar_t *wide = utf8_path_to_wide(path);
	wchar_t pattern[MAX_PATH + 3];
	size_t length;
	if (!wide) return NULL;
	length = wcslen(wide);
	if (length == 0 || length + 3 > sizeof(pattern) / sizeof(pattern[0])) {
		HeapFree(GetProcessHeap(), 0, wide);
		errno = ENAMETOOLONG;
		return NULL;
	}
	wcscpy(pattern, wide);
	HeapFree(GetProcessHeap(), 0, wide);
	if (pattern[length - 1] != L'\\' && pattern[length - 1] != L'/')
		pattern[length++] = L'\\';
	pattern[length++] = L'*';
	pattern[length] = L'\0';
	directory = calloc(1, sizeof(*directory));
	if (!directory) {
		errno = ENOMEM;
		return NULL;
	}
	directory->find = FindFirstFileW(pattern, &directory->data);
	if (directory->find == INVALID_HANDLE_VALUE) {
		set_errno_from_find_error(GetLastError());
		free(directory);
		return NULL;
	}
	directory->first = 1;
	return (DIR *)directory;
}

struct dirent *dropbear_win_utf8_readdir(DIR *opaque) {
	struct dropbear_win_utf8_dir *directory =
		(struct dropbear_win_utf8_dir *)opaque;
	int length;
	if (!directory) {
		errno = EINVAL;
		return NULL;
	}
	if (directory->first) {
		directory->first = 0;
	} else if (!FindNextFileW(directory->find, &directory->data)) {
		DWORD error = GetLastError();
		if (error != ERROR_NO_MORE_FILES) set_errno_from_find_error(error);
		return NULL;
	}
	length = WideCharToMultiByte(CP_UTF8, 0, directory->data.cFileName, -1,
		directory->entry.d_name, sizeof(directory->entry.d_name), NULL, NULL);
	if (length <= 0) {
		errno = EINVAL;
		return NULL;
	}
	directory->entry.d_ino = 1;
	directory->entry.d_reclen = 0;
	directory->entry.d_namlen = (unsigned short)(length - 1);
	return (struct dirent *)&directory->entry;
}

int dropbear_win_utf8_closedir(DIR *opaque) {
	struct dropbear_win_utf8_dir *directory =
		(struct dropbear_win_utf8_dir *)opaque;
	int result;
	if (!directory) {
		errno = EINVAL;
		return -1;
	}
	result = FindClose(directory->find) ? 0 : -1;
	if (result != 0) set_errno_from_find_error(GetLastError());
	free(directory);
	return result;
}

int dropbear_win_link(const char *existing_path, const char *new_path) {
	if (CreateHardLinkA(new_path, existing_path, NULL)) return 0;
	errno = EACCES;
	return -1;
}
int dropbear_win_ftruncate(int fd, __int64 size) {
	errno_t result = _chsize_s(fd, size);
	if (result != 0) errno = result;
	return result == 0 ? 0 : -1;
}
int dropbear_win_utimes(const char *path, const struct timeval times[2]) {
	struct __utimbuf64 values;
	if (!times) return _utime64(path, NULL);
	values.actime = times[0].tv_sec;
	values.modtime = times[1].tv_sec;
	return _utime64(path, &values);
}
int dropbear_win_nanosleep(const struct timespec *requested, struct timespec *remaining) {
	DWORD milliseconds;
	if (!requested) {
		errno = EINVAL;
		return -1;
	}
	milliseconds = (DWORD)(requested->tv_sec * 1000 +
		(requested->tv_nsec + 999999) / 1000000);
	Sleep(milliseconds);
	if (remaining) memset(remaining, 0, sizeof(*remaining));
	return 0;
}
int dropbear_win_fork(void) { errno = ENOSYS; return -1; }
int dropbear_win_execvp(const char *file, char *const argv[]) {
	(void)file; (void)argv; errno = ENOSYS; return -1;
}
int sigaction(int sig, const struct sigaction *action, struct sigaction *old_action) {
	(void)sig; (void)action; (void)old_action; return 0;
}
int dropbear_win_sigemptyset(int *set) { if (set) *set = 0; return 0; }
int dropbear_win_getrlimit(int resource, struct rlimit *limit) {
	(void)resource; if (limit) limit->rlim_cur = limit->rlim_max = 0; return 0;
}
int dropbear_win_setrlimit(int resource, const struct rlimit *limit) {
	(void)resource; (void)limit; return 0;
}
int dropbear_win_daemon(int nochdir, int noclose) { (void)nochdir; (void)noclose; return 0; }
int dropbear_win_setsid(void) { return 0; }
int dropbear_win_getuid(void) { return 0; }
int dropbear_win_geteuid(void) { return 0; }
int dropbear_win_getgid(void) { return 0; }
int dropbear_win_getegid(void) { return 0; }
int dropbear_win_setuid(uid_t uid) { (void)uid; return 0; }
int dropbear_win_setgid(gid_t gid) { (void)gid; return 0; }
int dropbear_win_initgroups(const char *user, gid_t group) { (void)user; (void)group; return 0; }
struct passwd *dropbear_win_getpwnam(const char *name) { (void)name; return NULL; }
struct passwd *dropbear_win_getpwuid(uid_t uid) { (void)uid; return NULL; }
struct group *dropbear_win_getgrnam(const char *name) { (void)name; return NULL; }
void dropbear_win_openlog(const char *ident, int option, int facility) {
	(void)ident; (void)option; (void)facility;
}
void dropbear_win_closelog(void) { }
void dropbear_win_syslog(int priority, const char *format, ...) {
	va_list args;
	(void)priority;
	va_start(args, format);
	vfprintf(stderr, format, args);
	fputc('\n', stderr);
	va_end(args);
}

/* Flood hardening. Defaults bound how much pre-authentication resource a
 * connect-and-idle or reconnect flood can demand; tests may override the
 * knobs in the environment before the listener starts. */

unsigned int dropbear_win_env_uint(const char *name, unsigned int fallback,
	unsigned int low, unsigned int high) {
	char buffer[16];
	char *end = NULL;
	unsigned long value;
	DWORD count = GetEnvironmentVariableA(name, buffer, sizeof(buffer));
	if (count == 0 || count >= sizeof(buffer)) return fallback;
	value = strtoul(buffer, &end, 10);
	if (!end || end == buffer || *end) return fallback;
	if (value < low) value = low;
	if (value > high) value = high;
	return (unsigned int)value;
}

/* Concurrent unauthenticated connection processes. Compiled-in slots stay at
 * MAX_UNAUTH_CLIENTS; the effective default is far below it. */
unsigned int dropbear_win_unauth_total(void) {
	static unsigned int cached;
	if (!cached) cached = dropbear_win_env_uint("DROPBEAR_WIN_MAX_UNAUTH",
		5, 1, MAX_UNAUTH_CLIENTS);
	return cached;
}

unsigned int dropbear_win_unauth_per_ip(void) {
	static unsigned int cached;
	/* Parallel automation from a single workstation is a primary use case,
	 * so the per-address default matches the total: the total cap binds
	 * first. Tighten it per deployment via the environment. */
	if (!cached) cached = dropbear_win_env_uint("DROPBEAR_WIN_MAX_UNAUTH_PER_IP",
		5, 1, dropbear_win_unauth_total());
	return cached;
}

/* Absolute grace from connection start to completed authentication. Activity
 * cannot extend it, so a dribbling client cannot hold a slot indefinitely. */
unsigned int dropbear_win_auth_grace(void) {
	static unsigned int cached;
	if (!cached) cached = dropbear_win_env_uint("DROPBEAR_WIN_AUTH_TIMEOUT",
		60, 1, 600);
	return cached;
}

/* Rate-limited diagnostic for the listener's flood rejection paths. */
void dropbear_win_trace_limits(const char *reason) {
	static char last_reason[32];
	static DWORD last_tick;
	DWORD now = GetTickCount();
	if (!dropbear_win_trace_enabled()) return;
	if (now - last_tick < 1000 && strcmp(reason, last_reason) == 0) return;
	strncpy(last_reason, reason, sizeof(last_reason) - 1);
	last_reason[sizeof(last_reason) - 1] = 0;
	last_tick = now;
	dropbear_win_logf("connection rejected: %s", reason);
}

int dropbear_win_trace_enabled(void) {
	static int cached;
	if (!cached) {
		char buffer[4];
		cached = GetEnvironmentVariableA("DROPBEAR_WIN_TRACE_LIMITS", buffer,
			sizeof(buffer)) ? 2 : 1;
	}
	return cached - 1;
}

/* Token bucket for starting connection processes. A reconnect flood which
 * drops and re-opens sessions as fast as slots are reaped would otherwise
 * make the listener spawn processes at its own maximum rate; the budget caps
 * that CPU amplification. Excess connections are closed immediately, like
 * over-limit ones. */
int dropbear_win_spawn_budget_take(void) {
	static DWORD last_tick;
	static unsigned int credit;
	unsigned int rate = dropbear_win_env_uint("DROPBEAR_WIN_CONN_RATE", 10, 1, 200);
	unsigned int burst = rate * 2 > 32 ? 32 : rate * 2;
	DWORD elapsed;
	if (!last_tick) {
		last_tick = GetTickCount();
		credit = burst;
	}
	elapsed = GetTickCount() - last_tick;
	if (elapsed > 60000) elapsed = 60000;
	if (elapsed) {
		unsigned int gained = (unsigned int)elapsed * rate / 1000;
		if (gained) {
			credit = credit + gained > burst ? burst : credit + gained;
			/* Advance the clock only by the time actually converted, so a
			 * slow drain never loses fractional tokens: queued connections
			 * poll this every 100 ms and must still refill at rate=1. */
			last_tick += (DWORD)(gained * 1000 / rate);
		}
	}
	if (!credit) return 0;
	credit--;
	return 1;
}
