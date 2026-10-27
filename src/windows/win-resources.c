/* Login-time resource snapshot; no helper programs or runtime dependencies. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"

static ULONGLONG ticks(FILETIME value) {
	return ((ULONGLONG)value.dwHighDateTime << 32) | value.dwLowDateTime;
}

void dropbear_win_resource_summary(char *output, size_t size) {
	typedef BOOL (WINAPI *system_times_fn)(LPFILETIME, LPFILETIME, LPFILETIME);
	HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
	system_times_fn system_times = (system_times_fn)(void *)GetProcAddress(kernel, "GetSystemTimes");
	FILETIME idle1, kernel1, user1, idle2, kernel2, user2;
	SYSTEM_INFO info;
	MEMORYSTATUSEX memory;
	ULARGE_INTEGER available, total, free_bytes;
	SYSTEMTIME now;
	char cpu[160] = "unavailable", ram[160] = "unavailable", disk[200] = "unavailable";
	GetSystemInfo(&info);
	/* Kernel time includes idle time. A short delta is meaningful; lifetime
	 * accumulated CPU time is not current utilization. */
	if (system_times && system_times(&idle1, &kernel1, &user1)) {
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
	if (GlobalMemoryStatusEx(&memory))
		snprintf(ram, sizeof(ram), "%.2f / %.2f GiB used (%lu%%), %.2f GiB available",
			(double)(memory.ullTotalPhys - memory.ullAvailPhys) / 1073741824.0,
			(double)memory.ullTotalPhys / 1073741824.0, (unsigned long)memory.dwMemoryLoad,
			(double)memory.ullAvailPhys / 1073741824.0);
	/* NULL selects the current directory's volume, including mounted volumes.
	 * Report caller-visible totals/free space consistently when quotas apply. */
	if (GetDiskFreeSpaceExW(NULL, &available, &total, &free_bytes) && total.QuadPart)
		snprintf(disk, sizeof(disk), "%.2f / %.2f GiB used (%.1f%%), %.2f GiB available",
			(double)(total.QuadPart - available.QuadPart) / 1073741824.0,
			(double)total.QuadPart / 1073741824.0,
			100.0 * (double)(total.QuadPart - available.QuadPart) / (double)total.QuadPart,
			(double)available.QuadPart / 1073741824.0);
	GetLocalTime(&now);
	snprintf(output, size,
		" Snapshot:     %04u-%02u-%02u %02u:%02u:%02u (server local time)\r\n"
		" CPU:          %lu logical processors; %s\r\n"
		" Memory:       %s\r\n"
		" Disk (cwd):   %s\r\n",
		now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
		(unsigned long)info.dwNumberOfProcessors, cpu, ram, disk);
}
#endif
