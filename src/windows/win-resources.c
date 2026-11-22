/* Windows system queries and login-time resource snapshot. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
#include "win-account.h"

static ULONGLONG ticks(FILETIME value) {
	return ((ULONGLONG)value.dwHighDateTime << 32) | value.dwLowDateTime;
}

enum resource_fields {
	RESOURCE_CPU = 1,
	RESOURCE_MEMORY = 2,
	RESOURCE_DISK = 4,
	RESOURCE_ALL = RESOURCE_CPU | RESOURCE_MEMORY | RESOURCE_DISK
};

static void resource_summary(char *output, size_t size, unsigned int fields) {
	typedef BOOL (WINAPI *system_times_fn)(LPFILETIME, LPFILETIME, LPFILETIME);
	HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
	system_times_fn system_times = (system_times_fn)(void *)GetProcAddress(kernel, "GetSystemTimes");
	FILETIME idle1, kernel1, user1, idle2, kernel2, user2;
	SYSTEM_INFO info;
	MEMORYSTATUSEX memory;
	ULARGE_INTEGER available, total;
	SYSTEMTIME now;
	char cpu_line[224] = "", ram_line[192] = "", disk_line[232] = "";
	char cpu[160] = "unavailable", ram[160] = "unavailable", disk[200] = "unavailable";
	/* Kernel time includes idle time. A short delta is meaningful; lifetime
	 * accumulated CPU time is not current utilization. */
	if ((fields & RESOURCE_CPU) && system_times && system_times(&idle1, &kernel1, &user1)) {
		Sleep(200);
		if (system_times(&idle2, &kernel2, &user2)) {
			ULONGLONG elapsed = ticks(kernel2) - ticks(kernel1) + ticks(user2) - ticks(user1);
			ULONGLONG idle = ticks(idle2) - ticks(idle1);
			if (elapsed && idle <= elapsed)
				snprintf(cpu, sizeof(cpu), "%.1f%% busy (200 ms sample, current processor group)",
					100.0 * (double)(elapsed - idle) / (double)elapsed);
		}
	}
	memset(&memory, 0, sizeof(memory));
	memory.dwLength = sizeof(memory);
	if ((fields & RESOURCE_MEMORY) && GlobalMemoryStatusEx(&memory))
		snprintf(ram, sizeof(ram), "%.2f / %.2f GiB used (%lu%%), %.2f GiB available",
			(double)(memory.ullTotalPhys - memory.ullAvailPhys) / 1073741824.0,
			(double)memory.ullTotalPhys / 1073741824.0, (unsigned long)memory.dwMemoryLoad,
			(double)memory.ullAvailPhys / 1073741824.0);
	/* NULL selects the current directory's volume, including mounted volumes.
	 * Report caller-visible totals/free space consistently when quotas apply. */
	if ((fields & RESOURCE_DISK) && GetDiskFreeSpaceExW(NULL, &available, &total, NULL) && total.QuadPart)
		snprintf(disk, sizeof(disk), "%.2f / %.2f GiB used (%.1f%%), %.2f GiB available",
			(double)(total.QuadPart - available.QuadPart) / 1073741824.0,
			(double)total.QuadPart / 1073741824.0,
			100.0 * (double)(total.QuadPart - available.QuadPart) / (double)total.QuadPart,
			(double)available.QuadPart / 1073741824.0);
	if (fields & RESOURCE_CPU) {
		GetSystemInfo(&info);
		snprintf(cpu_line, sizeof(cpu_line), " CPU:          %lu logical processors; %s\r\n",
			(unsigned long)info.dwNumberOfProcessors, cpu);
	}
	if (fields & RESOURCE_MEMORY)
		snprintf(ram_line, sizeof(ram_line), " Memory:       %s\r\n", ram);
	if (fields & RESOURCE_DISK)
		snprintf(disk_line, sizeof(disk_line), " Disk (cwd):   %s\r\n", disk);
	GetLocalTime(&now);
	snprintf(output, size,
		" Snapshot:     %04u-%02u-%02u %02u:%02u:%02u (server local time)\r\n"
		"%s%s%s",
		now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
		cpu_line, ram_line, disk_line);
}

void dropbear_win_resource_summary(char *output, size_t size) {
	resource_summary(output, size, RESOURCE_ALL);
}

static const char *native_architecture(int uname_format) {
	SYSTEM_INFO info;
	GetNativeSystemInfo(&info);
	switch (info.wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64: return uname_format ? "x86_64" : "x64";
		case PROCESSOR_ARCHITECTURE_INTEL: return uname_format ? "i686" : "x86";
#ifdef PROCESSOR_ARCHITECTURE_ARM64
		case PROCESSOR_ARCHITECTURE_ARM64: return uname_format ? "aarch64" : "ARM64";
#endif
		case PROCESSOR_ARCHITECTURE_ARM: return uname_format ? "arm" : "ARM";
		default: return uname_format ? "unknown" : "unknown architecture";
	}
}

static int read_windows_version(OSVERSIONINFOW *version) {
	typedef LONG (WINAPI *rtl_get_version_fn)(OSVERSIONINFOW *);
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	rtl_get_version_fn get_version = ntdll
		? (rtl_get_version_fn)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
	memset(version, 0, sizeof(*version));
	version->dwOSVersionInfoSize = sizeof(*version);
	return get_version && get_version(version) == 0;
}

void dropbear_win_windows_version(char *output, size_t size) {
	OSVERSIONINFOW version;
	if (read_windows_version(&version)) {
		snprintf(output, size, "Windows NT %lu.%lu build %lu (%s)",
			(unsigned long)version.dwMajorVersion, (unsigned long)version.dwMinorVersion,
			(unsigned long)version.dwBuildNumber, native_architecture(0));
	} else {
		snprintf(output, size, "Windows (%s)", native_architecture(0));
	}
}

static void read_hostname(char *output, size_t size) {
	wchar_t name[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD length = sizeof(name) / sizeof(name[0]);
	if (!GetComputerNameW(name, &length) ||
			!WideCharToMultiByte(CP_UTF8, 0, name, -1, output, (int)size, NULL, NULL))
		snprintf(output, size, "unknown");
}

enum query_kind { QUERY_NONE, QUERY_UNAME, QUERY_SYSTEM, QUERY_CPU, QUERY_MEMORY, QUERY_DISK, QUERY_TOOLS };

static enum query_kind system_query_kind(const char *command, const char **options) {
	static const char *const names[] = { "uname", "sysinfo", "cpuinfo", "meminfo", "diskinfo", "toolsinfo" };
	size_t length, i;
	const char *args;
	if (!command) return QUERY_NONE;
	command += strspn(command, " \t");
	length = strcspn(command, " \t");
	args = command + length;
	args += strspn(args, " \t");
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (length != strlen(names[i]) || strncmp(command, names[i], length)) continue;
		/* Shell expressions, quoted arguments and paths stay with the shell. */
		if (i == 0) {
			if (strspn(args, " \t-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != strlen(args))
				return QUERY_NONE;
		} else if (*args) {
			return QUERY_NONE;
		}
		*options = args;
		return (enum query_kind)(QUERY_UNAME + i);
	}
	return QUERY_NONE;
}

int dropbear_win_is_system_query(const char *command) {
	const char *options;
	return system_query_kind(command, &options) != QUERY_NONE;
}

static int print_uname(const char *options) {
	static const char letters[] = "snrvmo";
	static const char *const long_options[] = {
		"--kernel-name", "--nodename", "--kernel-release", "--kernel-version",
		"--machine", "--operating-system", "--all", "--help"
	};
	static const char usage[] = "Usage: uname [-asnrvmo] [--help]\n";
	OSVERSIONINFOW version;
	char hostname[64], release[32] = "unknown", build[32] = "unknown";
	const char *values[] = { "Windows_NT", hostname, release, build, native_architecture(1), "Windows" };
	unsigned int fields = 0;
	unsigned int all_fields = (1U << (sizeof(letters) - 1)) - 1;
	size_t i;
	int printed = 0;
	while (*options) {
		size_t length = strcspn(options, " \t");
		if (length < 2 || options[0] != '-') goto invalid;
		if (options[1] == '-') {
			for (i = 0; i < sizeof(long_options) / sizeof(long_options[0]); i++) {
				if (length == strlen(long_options[i]) && !strncmp(options, long_options[i], length)) break;
			}
			if (i < sizeof(letters) - 1) fields |= 1U << i;
			else if (i == sizeof(letters) - 1) fields |= all_fields;
			else if (i == sizeof(letters)) { fputs(usage, stdout); return 0; }
			else goto invalid;
		} else {
			for (i = 1; i < length; i++) {
				const char *flag = strchr(letters, options[i]);
				if (flag) fields |= 1U << (flag - letters);
				else if (options[i] == 'a') fields |= all_fields;
				else goto invalid;
			}
		}
		options += length;
		options += strspn(options, " \t");
	}
	if (!fields) fields = 1;
	read_hostname(hostname, sizeof(hostname));
	if (read_windows_version(&version)) {
		snprintf(release, sizeof(release), "%lu.%lu", (unsigned long)version.dwMajorVersion,
			(unsigned long)version.dwMinorVersion);
		snprintf(build, sizeof(build), "%lu", (unsigned long)version.dwBuildNumber);
	}
	for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
		if (!(fields & (1U << i))) continue;
		if (printed) fputc(' ', stdout);
		fputs(values[i], stdout);
		printed = 1;
	}
	fputc('\n', stdout);
	return 0;
invalid:
	fputs(usage, stderr);
	return 2;
}

int dropbear_win_system_query(const char *command) {
	const char *options;
	enum query_kind query = system_query_kind(command, &options);
	char resources[1024];
	unsigned int fields = RESOURCE_ALL;
	switch (query) {
		case QUERY_UNAME: return print_uname(options);
		case QUERY_SYSTEM: {
			char hostname[64], version[160];
			read_hostname(hostname, sizeof(hostname));
			dropbear_win_windows_version(version, sizeof(version));
			printf(" Host:         %s\n System:       %s\n Binary:       %s\n",
				hostname, version, dropbear_win_binary_architecture());
			break;
		}
		case QUERY_CPU: fields = RESOURCE_CPU; break;
		case QUERY_MEMORY: fields = RESOURCE_MEMORY; break;
		case QUERY_DISK: fields = RESOURCE_DISK; break;
		case QUERY_TOOLS:
			dropbear_win_print_tools_json(stdout);
			fputc('\n', stdout);
			return 0;
		default: return 2;
	}
	resource_summary(resources, sizeof(resources), fields);
	/* The MOTD writes CRLF directly to SSH. The CRT supplies CRLF on stdout. */
	for (const char *p = resources; *p; p++)
		if (*p != '\r') fputc(*p, stdout);
	return 0;
}
#endif
