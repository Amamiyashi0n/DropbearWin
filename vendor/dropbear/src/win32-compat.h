#ifndef DROPBEAR_WIN32_COMPAT_H_
#define DROPBEAR_WIN32_COMPAT_H_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif
#ifdef interface
#undef interface
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#ifdef interface
#undef interface
#endif

#include <direct.h>
#include <io.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <process.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utime.h>
#include <dirent.h>
#include <time.h>
#include <stdarg.h>
#include <setjmp.h>
#include <assert.h>

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#endif

#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x4000
#endif
#ifndef FD_CLOEXEC
#define FD_CLOEXEC 1
#endif
#ifndef F_GETFL
#define F_GETFL 3
#define F_SETFL 4
#define F_SETFD 2
#endif

#ifndef S_ISDIR
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
#endif
#ifndef S_ISUID
#define S_ISUID 04000
#define S_ISGID 02000
#endif

struct passwd {
	char *pw_name;
	char *pw_passwd;
	uid_t pw_uid;
	gid_t pw_gid;
	char *pw_gecos;
	char *pw_dir;
	char *pw_shell;
};

struct group {
	char *gr_name;
	char *gr_passwd;
	gid_t gr_gid;
	char **gr_mem;
};

struct rlimit {
	unsigned long rlim_cur;
	unsigned long rlim_max;
};

struct sigaction {
	void (*sa_handler)(int);
	int sa_flags;
	int sa_mask;
};

struct winsize {
	unsigned short ws_row;
	unsigned short ws_col;
	unsigned short ws_xpixel;
	unsigned short ws_ypixel;
};

typedef long suseconds_t;

typedef struct dropbear_win_once {
	volatile LONG state;
} dropbear_win_once;

typedef int (*dropbear_win_once_initializer)(void);

#define DROPBEAR_WIN_ONCE_INIT {0}

struct termios {
	unsigned long c_iflag;
	unsigned long c_oflag;
	unsigned long c_cflag;
	unsigned long c_lflag;
	unsigned char c_cc[32];
};

#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef PF_UNIX
#define PF_UNIX AF_UNIX
#endif
struct sockaddr_un {
	short sun_family;
	char sun_path[108];
};

struct iovec {
	void *iov_base;
	size_t iov_len;
};
#define UIO_MAXIOV 64

#define RLIMIT_CORE 0
#define SA_NOCLDSTOP 0
#define WNOHANG 1
#define SIGCHLD SIGTERM
#define SIGPIPE SIGTERM
#ifndef SIGALRM
#define SIGALRM 14
#define SIGBUS 7
#define SIGHUP 1
#define SIGKILL 9
#define SIGQUIT 3
#define SIGTRAP 5
#define SIGUSR1 10
#define SIGUSR2 12
#endif
#define LOG_EMERG 0
#define LOG_ALERT 1
#define LOG_CRIT 2
#define LOG_ERR 3
#define LOG_WARNING 4
#define LOG_NOTICE 5
#define LOG_INFO 6
#define LOG_DEBUG 7
#define LOG_AUTH 0
#define LOG_AUTHPRIV LOG_AUTH
#define LOG_PID 0
#define TCSANOW 0
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#define SHUT_RDWR SD_BOTH

#ifndef WIFEXITED
#define WIFEXITED(status) (1)
#define WEXITSTATUS(status) (status)
#define WIFSIGNALED(status) (0)
#define WTERMSIG(status) (0)
#endif

#define getcwd _getcwd
#define chdir _chdir
#define getpid _getpid
#define unlink _unlink
#define dup _dup
#define dup2 _dup2
#define isatty _isatty
#define fileno _fileno
#define lseek _lseek
#define stat _stat64
#define fstat _fstat64
#define chmod _chmod
#define mkdir(path, mode) _mkdir(path)
#define umask _umask
#define fsync _commit
#define putenv _putenv
#define tzset _tzset
#define sleep(seconds) (Sleep((DWORD)(seconds) * 1000), 0)
#define strcasecmp _stricmp
#define strncasecmp _strnicmp

int dropbear_win_startup(void);
int dropbear_win_once_run(dropbear_win_once *once,
		dropbear_win_once_initializer initializer);
int dropbear_win_socket(int af, int type, int protocol);
int dropbear_win_accept(int fd, struct sockaddr *addr, int *addrlen);
int dropbear_win_bind(int fd, const struct sockaddr *addr, int addrlen);
int dropbear_win_listen(int fd, int backlog);
int dropbear_win_connect(int fd, const struct sockaddr *addr, int addrlen);
int dropbear_win_select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, const struct timeval *timeout);
int dropbear_win_setsockopt(int fd, int level, int optname,
		const void *optval, int optlen);
int dropbear_win_getsockopt(int fd, int level, int optname,
		void *optval, int *optlen);
int dropbear_win_getsockname(int fd, struct sockaddr *addr, int *addrlen);
int dropbear_win_getpeername(int fd, struct sockaddr *addr, int *addrlen);
int dropbear_win_shutdown(int fd, int how);
int dropbear_win_socketpair(int fds[2]);
int dropbear_win_export_socket(int fd, DWORD target_pid, WSAPROTOCOL_INFOW *info);
int dropbear_win_import_socket(const WSAPROTOCOL_INFOW *info);
int dropbear_win_random(void *buffer, unsigned int length);
int dropbear_win_gettimeofday(struct timeval *tv, void *timezone);
int dropbear_win_spawn_shell(const char *command, const char *ssh_user,
		const char *terminal, const char *connection,
		int *writefd, int *readfd, int *errfd, pid_t *pid);
int dropbear_win_spawn_connection(int socket_fd, int auth_fd, int argc, char **argv);
int dropbear_win_exec_main(void);
int dropbear_win_desktop_launch_main(void);
int dropbear_win_receive_connection(const char *pipe_handle_text, int *auth_fd);
void dropbear_win_process_cleanup(void);
void dropbear_win_resource_summary(char *output, size_t size);
extern int dropbear_win_takeover_enabled;
int dropbear_win_bind_listener(int fd, const struct sockaddr *address, int length);
int dropbear_win_startup_lock(void);
void dropbear_win_startup_unlock(void);
HANDLE dropbear_win_log_handle(void);
void dropbear_win_log_adopt(HANDLE mutex);
void dropbear_win_logf(const char *format, ...);
void dropbear_win_reap_connections(void);
int dropbear_win_service_main(int argc, char **argv);
int dropbear_win_is_service(void);
void dropbear_win_maybe_register_service(int argc, char **argv);
int dropbear_win_install_autostart(int argc, char **argv);
int dropbear_win_uninstall(int argc, char **argv);
wchar_t *dropbear_win_build_service_command_line(const wchar_t *executable,
	int argc, char **argv);
wchar_t *dropbear_win_build_autostart_relaunch_parameters(int argc, char **argv);
int dropbear_win_listener_init(void);
int dropbear_win_stop_requested(void);
void dropbear_win_listener_ready(void);
void dropbear_win_service_stopped(int code);
pid_t dropbear_win_waitpid(pid_t pid, int *status, int options);
int dropbear_win_kill(pid_t pid, int signal_number);
ssize_t dropbear_win_read(int fd, void *buf, size_t count);
ssize_t dropbear_win_write(int fd, const void *buf, size_t count);
int dropbear_win_close(int fd);
int dropbear_win_fcntl(int fd, int cmd, ...);
int dropbear_win_pipe(int fds[2]);
int dropbear_win_link(const char *existing_path, const char *new_path);
int dropbear_win_open(const char *path, int flags, ...);
int dropbear_win_utf8_open(const char *path, int flags, ...);
int dropbear_win_utf8_stat(const char *path, struct _stat64 *status);
int dropbear_win_utf8_chmod(const char *path, int mode);
int dropbear_win_utf8_mkdir(const char *path, int mode);
int dropbear_win_utf8_utimes(const char *path, const struct timeval times[2]);
DIR *dropbear_win_utf8_opendir(const char *path);
struct dirent *dropbear_win_utf8_readdir(DIR *directory);
int dropbear_win_utf8_closedir(DIR *directory);
int dropbear_win_ftruncate(int fd, __int64 size);
int dropbear_win_utimes(const char *path, const struct timeval times[2]);
int dropbear_win_nanosleep(const struct timespec *requested, struct timespec *remaining);
int dropbear_win_fork(void);
int dropbear_win_execvp(const char *file, char *const argv[]);
int sigaction(int sig, const struct sigaction *action,
		struct sigaction *old_action);
int dropbear_win_sigemptyset(int *set);
int dropbear_win_getrlimit(int resource, struct rlimit *limit);
int dropbear_win_setrlimit(int resource, const struct rlimit *limit);
int dropbear_win_daemon(int nochdir, int noclose);
int dropbear_win_setsid(void);
int dropbear_win_getuid(void);
int dropbear_win_geteuid(void);
int dropbear_win_getgid(void);
int dropbear_win_getegid(void);
int dropbear_win_setuid(uid_t uid);
int dropbear_win_setgid(gid_t gid);
int dropbear_win_initgroups(const char *user, gid_t group);
struct passwd *dropbear_win_getpwnam(const char *name);
struct passwd *dropbear_win_getpwuid(uid_t uid);
struct group *dropbear_win_getgrnam(const char *name);
void dropbear_win_openlog(const char *ident, int option, int facility);
void dropbear_win_closelog(void);
void dropbear_win_syslog(int priority, const char *format, ...);

unsigned int dropbear_win_env_uint(const char *name, unsigned int fallback,
	unsigned int low, unsigned int high);
unsigned int dropbear_win_unauth_total(void);
unsigned int dropbear_win_unauth_per_ip(void);
unsigned int dropbear_win_auth_grace(void);
int dropbear_win_spawn_budget_take(void);
void dropbear_win_trace_limits(const char *reason);
int dropbear_win_trace_enabled(void);

#ifndef DROPBEAR_WIN32_COMPAT_IMPL
#define socket dropbear_win_socket
#define accept dropbear_win_accept
#define bind dropbear_win_bind
#define listen dropbear_win_listen
#define connect dropbear_win_connect
#define select dropbear_win_select
#define setsockopt dropbear_win_setsockopt
#define getsockopt dropbear_win_getsockopt
#define getsockname dropbear_win_getsockname
#define getpeername dropbear_win_getpeername
#define shutdown dropbear_win_shutdown
#define read dropbear_win_read
#define write dropbear_win_write
#define close dropbear_win_close
#define fcntl dropbear_win_fcntl
#define pipe dropbear_win_pipe
#define link dropbear_win_link
#define open dropbear_win_open
#define ftruncate dropbear_win_ftruncate
#define utimes dropbear_win_utimes
#define nanosleep dropbear_win_nanosleep
#define fork dropbear_win_fork
#define execvp dropbear_win_execvp
#define sigemptyset dropbear_win_sigemptyset
#define getrlimit dropbear_win_getrlimit
#define setrlimit dropbear_win_setrlimit
#define daemon dropbear_win_daemon
#define setsid dropbear_win_setsid
#define getuid dropbear_win_getuid
#define geteuid dropbear_win_geteuid
#define getgid dropbear_win_getgid
#define getegid dropbear_win_getegid
#define setuid dropbear_win_setuid
#define setgid dropbear_win_setgid
#define initgroups dropbear_win_initgroups
#define getpwnam dropbear_win_getpwnam
#define getpwuid dropbear_win_getpwuid
#define getgrnam dropbear_win_getgrnam
#define openlog dropbear_win_openlog
#define closelog dropbear_win_closelog
#define syslog dropbear_win_syslog
#define gettimeofday dropbear_win_gettimeofday
#define waitpid dropbear_win_waitpid
#define kill dropbear_win_kill
#define tcgetattr(fd, termios_ptr) (-1)
#define tcsetattr(fd, action, termios_ptr) (-1)
#define vfork() (-1)
#endif

#endif
