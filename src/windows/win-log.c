/* The listener and its connection processes share a logging mutex. */
#include "includes.h"
#ifdef DROPBEAR_WIN32_NATIVE
#include "win32-compat.h"
static HANDLE log_mutex;

HANDLE dropbear_win_log_handle(void) {
	if (!log_mutex) {
		SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
		log_mutex = CreateMutexW(&security, FALSE, NULL);
	}
	return log_mutex;
}
void dropbear_win_log_adopt(HANDLE mutex) { log_mutex = mutex; }

void dropbear_win_logf(const char *format, ...) {
	char line[4096];
	va_list args;
	DWORD written, result;
	HANDLE mutex = dropbear_win_log_handle();
	HANDLE output = (HANDLE)_get_osfhandle(_fileno(stderr));
	size_t length, offset = 0;
	va_start(args, format);
	vsnprintf(line, sizeof(line), format, args);
	va_end(args);
	line[sizeof(line)-1] = 0;
	length = strlen(line);
	result = mutex ? WaitForSingleObject(mutex, 5000) : WAIT_FAILED;
	/* One fully formatted write also avoids the CRT's character-wise console
	 * writes. Preserve progress even when the destination has been closed. */
	while (offset < length && WriteFile(output, line + offset, (DWORD)(length-offset), &written, NULL) && written)
		offset += written;
	if (result == WAIT_OBJECT_0 || result == WAIT_ABANDONED) ReleaseMutex(mutex);
}
#endif
