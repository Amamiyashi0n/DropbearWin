#include "includes.h"

#ifdef DROPBEAR_WIN32_NATIVE

#define SFTP_MAX_PACKET (1024U * 1024U)
#define SFTP_MAX_IO (256U * 1024U)
#define SFTP_HANDLE_COUNT 128

#define SSH_FXP_INIT 1
#define SSH_FXP_VERSION 2
#define SSH_FXP_OPEN 3
#define SSH_FXP_CLOSE 4
#define SSH_FXP_READ 5
#define SSH_FXP_WRITE 6
#define SSH_FXP_LSTAT 7
#define SSH_FXP_FSTAT 8
#define SSH_FXP_SETSTAT 9
#define SSH_FXP_FSETSTAT 10
#define SSH_FXP_OPENDIR 11
#define SSH_FXP_READDIR 12
#define SSH_FXP_REMOVE 13
#define SSH_FXP_MKDIR 14
#define SSH_FXP_RMDIR 15
#define SSH_FXP_REALPATH 16
#define SSH_FXP_STAT 17
#define SSH_FXP_RENAME 18
#define SSH_FXP_READLINK 19
#define SSH_FXP_SYMLINK 20
#define SSH_FXP_STATUS 101
#define SSH_FXP_HANDLE 102
#define SSH_FXP_DATA 103
#define SSH_FXP_NAME 104
#define SSH_FXP_ATTRS 105
#define SSH_FXP_EXTENDED 200

#define SSH_FX_OK 0
#define SSH_FX_EOF 1
#define SSH_FX_NO_SUCH_FILE 2
#define SSH_FX_PERMISSION_DENIED 3
#define SSH_FX_FAILURE 4
#define SSH_FX_BAD_MESSAGE 5
#define SSH_FX_OP_UNSUPPORTED 8

#define SSH_FILEXFER_ATTR_SIZE 0x00000001
#define SSH_FILEXFER_ATTR_UIDGID 0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS 0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME 0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED 0x80000000

#define SSH_FXF_READ 0x00000001
#define SSH_FXF_WRITE 0x00000002
#define SSH_FXF_APPEND 0x00000004
#define SSH_FXF_CREAT 0x00000008
#define SSH_FXF_TRUNC 0x00000010
#define SSH_FXF_EXCL 0x00000020

#define SFTP_MODE_DIRECTORY 0040000U
#define SFTP_MODE_REGULAR 0100000U

struct sftp_reader {
	const unsigned char *data;
	size_t length;
	size_t position;
};

struct sftp_builder {
	unsigned char *data;
	size_t length;
	size_t capacity;
	int failed;
};

struct sftp_attrs {
	uint32_t flags;
	uint64_t size;
	uint32_t permissions;
	uint32_t atime;
	uint32_t mtime;
};

enum sftp_handle_kind {
	SFTP_HANDLE_NONE,
	SFTP_HANDLE_FILE,
	SFTP_HANDLE_DIRECTORY
};

struct sftp_handle {
	enum sftp_handle_kind kind;
	uint32_t generation;
	HANDLE file;
	HANDLE find;
	WIN32_FIND_DATAW find_data;
	int have_find_data;
	wchar_t *directory;
};

static struct sftp_handle sftp_handles[SFTP_HANDLE_COUNT];
static uint32_t sftp_generation = 1;

static uint32_t load_u32(const unsigned char *data) {
	return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
		((uint32_t)data[2] << 8) | data[3];
}

static uint64_t load_u64(const unsigned char *data) {
	return ((uint64_t)load_u32(data) << 32) | load_u32(data + 4);
}

static void store_u32(unsigned char *data, uint32_t value) {
	data[0] = (unsigned char)(value >> 24);
	data[1] = (unsigned char)(value >> 16);
	data[2] = (unsigned char)(value >> 8);
	data[3] = (unsigned char)value;
}

static void store_u64(unsigned char *data, uint64_t value) {
	store_u32(data, (uint32_t)(value >> 32));
	store_u32(data + 4, (uint32_t)value);
}

static int read_exact(HANDLE handle, void *output, DWORD length) {
	unsigned char *position = output;
	while (length) {
		DWORD count = 0;
		if (!ReadFile(handle, position, length, &count, NULL) || count == 0) return 0;
		position += count;
		length -= count;
	}
	return 1;
}

static int write_exact(HANDLE handle, const void *input, DWORD length) {
	const unsigned char *position = input;
	while (length) {
		DWORD count = 0;
		if (!WriteFile(handle, position, length, &count, NULL) || count == 0) return 0;
		position += count;
		length -= count;
	}
	return 1;
}

static int reader_bytes(struct sftp_reader *reader, size_t length,
		const unsigned char **value) {
	if (length > reader->length - reader->position) return 0;
	*value = reader->data + reader->position;
	reader->position += length;
	return 1;
}

static int reader_u32(struct sftp_reader *reader, uint32_t *value) {
	const unsigned char *bytes;
	if (!reader_bytes(reader, 4, &bytes)) return 0;
	*value = load_u32(bytes);
	return 1;
}

static int reader_u64(struct sftp_reader *reader, uint64_t *value) {
	const unsigned char *bytes;
	if (!reader_bytes(reader, 8, &bytes)) return 0;
	*value = load_u64(bytes);
	return 1;
}

static int reader_string_view(struct sftp_reader *reader,
		const unsigned char **value, uint32_t *length) {
	if (!reader_u32(reader, length)) return 0;
	return reader_bytes(reader, *length, value);
}

static char *reader_string(struct sftp_reader *reader) {
	const unsigned char *value;
	uint32_t length;
	char *result;
	if (!reader_string_view(reader, &value, &length) ||
		memchr(value, '\0', length) != NULL) return NULL;
	result = malloc((size_t)length + 1);
	if (!result) return NULL;
	memcpy(result, value, length);
	result[length] = '\0';
	return result;
}

static int reader_attrs(struct sftp_reader *reader, struct sftp_attrs *attrs) {
	uint32_t ignored;
	uint32_t extended_count;
	const unsigned char *extended;
	uint32_t extended_length;
	memset(attrs, 0, sizeof(*attrs));
	if (!reader_u32(reader, &attrs->flags)) return 0;
	if ((attrs->flags & SSH_FILEXFER_ATTR_SIZE) &&
		!reader_u64(reader, &attrs->size)) return 0;
	if (attrs->flags & SSH_FILEXFER_ATTR_UIDGID) {
		if (!reader_u32(reader, &ignored) || !reader_u32(reader, &ignored)) return 0;
	}
	if ((attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS) &&
		!reader_u32(reader, &attrs->permissions)) return 0;
	if (attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME) {
		if (!reader_u32(reader, &attrs->atime) ||
			!reader_u32(reader, &attrs->mtime)) return 0;
	}
	if (attrs->flags & SSH_FILEXFER_ATTR_EXTENDED) {
		if (!reader_u32(reader, &extended_count) || extended_count > 1024) return 0;
		while (extended_count--) {
			if (!reader_string_view(reader, &extended, &extended_length) ||
				!reader_string_view(reader, &extended, &extended_length)) return 0;
		}
	}
	return 1;
}

static void builder_reserve(struct sftp_builder *builder, size_t extra) {
	size_t capacity;
	unsigned char *resized;
	if (builder->failed || extra > SFTP_MAX_PACKET + 4 - builder->length) {
		builder->failed = 1;
		return;
	}
	if (builder->length + extra <= builder->capacity) return;
	capacity = builder->capacity ? builder->capacity : 256;
	while (capacity < builder->length + extra) capacity *= 2;
	if (capacity > SFTP_MAX_PACKET + 4) capacity = SFTP_MAX_PACKET + 4;
	resized = realloc(builder->data, capacity);
	if (!resized) {
		builder->failed = 1;
		return;
	}
	builder->data = resized;
	builder->capacity = capacity;
}

static void builder_bytes(struct sftp_builder *builder, const void *data, size_t length) {
	builder_reserve(builder, length);
	if (builder->failed) return;
	memcpy(builder->data + builder->length, data, length);
	builder->length += length;
}

static void builder_u8(struct sftp_builder *builder, unsigned char value) {
	builder_bytes(builder, &value, 1);
}

static void builder_u32(struct sftp_builder *builder, uint32_t value) {
	unsigned char bytes[4];
	store_u32(bytes, value);
	builder_bytes(builder, bytes, sizeof(bytes));
}

static void builder_u64(struct sftp_builder *builder, uint64_t value) {
	unsigned char bytes[8];
	store_u64(bytes, value);
	builder_bytes(builder, bytes, sizeof(bytes));
}

static void builder_string_length(struct sftp_builder *builder,
		const void *value, uint32_t length) {
	builder_u32(builder, length);
	builder_bytes(builder, value, length);
}

static void builder_string(struct sftp_builder *builder, const char *value) {
	builder_string_length(builder, value, (uint32_t)strlen(value));
}

static void builder_begin(struct sftp_builder *builder, unsigned char type) {
	memset(builder, 0, sizeof(*builder));
	builder_reserve(builder, 5);
	if (builder->failed) return;
	builder->length = 4;
	builder_u8(builder, type);
}

static int builder_send(struct sftp_builder *builder, HANDLE output) {
	int result;
	if (builder->failed || builder->length < 5) {
		free(builder->data);
		return 0;
	}
	store_u32(builder->data, (uint32_t)(builder->length - 4));
	result = write_exact(output, builder->data, (DWORD)builder->length);
	free(builder->data);
	return result;
}

static uint32_t status_from_error(DWORD error) {
	switch (error) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
		case ERROR_INVALID_DRIVE:
		case ERROR_BAD_NETPATH:
			return SSH_FX_NO_SUCH_FILE;
		case ERROR_ACCESS_DENIED:
		case ERROR_SHARING_VIOLATION:
		case ERROR_WRITE_PROTECT:
			return SSH_FX_PERMISSION_DENIED;
		default:
			return SSH_FX_FAILURE;
	}
}

static const char *status_message(uint32_t status) {
	switch (status) {
		case SSH_FX_OK: return "Success";
		case SSH_FX_EOF: return "End of file";
		case SSH_FX_NO_SUCH_FILE: return "No such file or directory";
		case SSH_FX_PERMISSION_DENIED: return "Permission denied";
		case SSH_FX_BAD_MESSAGE: return "Malformed SFTP request";
		case SSH_FX_OP_UNSUPPORTED: return "Operation unsupported";
		default: return "Windows file operation failed";
	}
}

static int send_status(HANDLE output, uint32_t id, uint32_t status) {
	struct sftp_builder builder;
	builder_begin(&builder, SSH_FXP_STATUS);
	builder_u32(&builder, id);
	builder_u32(&builder, status);
	builder_string(&builder, status_message(status));
	builder_string(&builder, "en-US");
	return builder_send(&builder, output);
}

static wchar_t *utf8_to_full_path(const char *path) {
	wchar_t *wide = NULL;
	wchar_t *full = NULL;
	const char *source = path && path[0] ? path : ".";
	int wide_length;
	DWORD full_length;
	size_t i;

	if (source[0] == '/' && ((source[1] >= 'A' && source[1] <= 'Z') ||
			(source[1] >= 'a' && source[1] <= 'z')) && source[2] == ':') source++;
	if (source[0] == '~' && (source[1] == '/' || source[1] == '\\')) source += 2;
	else if (strcmp(source, "~") == 0) source = ".";
	wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
		source, -1, NULL, 0);
	if (wide_length <= 0) return NULL;
	wide = malloc((size_t)wide_length * sizeof(*wide));
	if (!wide || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
			source, -1, wide, wide_length)) goto fail;
	for (i = 0; wide[i]; i++) if (wide[i] == L'/') wide[i] = L'\\';
	full_length = GetFullPathNameW(wide, 0, NULL, NULL);
	if (!full_length || full_length > 32767) goto fail;
	full = malloc(((size_t)full_length + 1) * sizeof(*full));
	if (!full || !GetFullPathNameW(wide, full_length + 1, full, NULL)) goto fail;
	free(wide);
	return full;

fail:
	free(wide);
	free(full);
	return NULL;
}

static char *wide_path_to_utf8(const wchar_t *path) {
	int length = WideCharToMultiByte(CP_UTF8, 0, path, -1, NULL, 0, NULL, NULL);
	char *result;
	int i;
	if (length <= 0) return NULL;
	result = malloc((size_t)length);
	if (!result || !WideCharToMultiByte(CP_UTF8, 0, path, -1,
			result, length, NULL, NULL)) {
		free(result);
		return NULL;
	}
	for (i = 0; result[i]; i++) if (result[i] == '\\') result[i] = '/';
	return result;
}

static uint64_t filetime_to_unix(FILETIME filetime) {
	ULARGE_INTEGER value;
	value.LowPart = filetime.dwLowDateTime;
	value.HighPart = filetime.dwHighDateTime;
	if (value.QuadPart < 116444736000000000ULL) return 0;
	return (value.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

static FILETIME unix_to_filetime(uint32_t seconds) {
	ULARGE_INTEGER value;
	FILETIME result;
	value.QuadPart = (uint64_t)seconds * 10000000ULL + 116444736000000000ULL;
	result.dwLowDateTime = value.LowPart;
	result.dwHighDateTime = value.HighPart;
	return result;
}

static void builder_attrs_values(struct sftp_builder *builder, uint64_t size,
		DWORD attributes, FILETIME access_time, FILETIME write_time) {
	uint32_t permissions = (attributes & FILE_ATTRIBUTE_DIRECTORY)
		? SFTP_MODE_DIRECTORY | 0755U : SFTP_MODE_REGULAR | 0644U;
	if (attributes & FILE_ATTRIBUTE_READONLY) permissions &= ~0222U;
	builder_u32(builder, SSH_FILEXFER_ATTR_SIZE |
		SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME);
	builder_u64(builder, size);
	builder_u32(builder, permissions);
	builder_u32(builder, (uint32_t)filetime_to_unix(access_time));
	builder_u32(builder, (uint32_t)filetime_to_unix(write_time));
}

static int builder_attrs_handle(struct sftp_builder *builder, HANDLE file) {
	BY_HANDLE_FILE_INFORMATION information;
	uint64_t size;
	if (!GetFileInformationByHandle(file, &information)) return 0;
	size = ((uint64_t)information.nFileSizeHigh << 32) | information.nFileSizeLow;
	builder_attrs_values(builder, size, information.dwFileAttributes,
		information.ftLastAccessTime, information.ftLastWriteTime);
	return 1;
}

static int builder_attrs_path(struct sftp_builder *builder, const wchar_t *path) {
	WIN32_FILE_ATTRIBUTE_DATA information;
	uint64_t size;
	if (!GetFileAttributesExW(path, GetFileExInfoStandard, &information)) return 0;
	size = ((uint64_t)information.nFileSizeHigh << 32) | information.nFileSizeLow;
	builder_attrs_values(builder, size, information.dwFileAttributes,
		information.ftLastAccessTime, information.ftLastWriteTime);
	return 1;
}

static void builder_attrs_find(struct sftp_builder *builder,
		const WIN32_FIND_DATAW *information) {
	uint64_t size = ((uint64_t)information->nFileSizeHigh << 32) |
		information->nFileSizeLow;
	builder_attrs_values(builder, size, information->dwFileAttributes,
		information->ftLastAccessTime, information->ftLastWriteTime);
}

static struct sftp_handle *allocate_handle(enum sftp_handle_kind kind,
		uint32_t *index_out) {
	uint32_t index;
	for (index = 0; index < SFTP_HANDLE_COUNT; index++) {
		if (sftp_handles[index].kind == SFTP_HANDLE_NONE) {
			struct sftp_handle *handle = &sftp_handles[index];
			memset(handle, 0, sizeof(*handle));
			handle->kind = kind;
			handle->file = INVALID_HANDLE_VALUE;
			handle->find = INVALID_HANDLE_VALUE;
			handle->generation = ++sftp_generation;
			if (handle->generation == 0) handle->generation = ++sftp_generation;
			*index_out = index;
			return handle;
		}
	}
	return NULL;
}

static void release_handle(struct sftp_handle *handle) {
	if (handle->file != INVALID_HANDLE_VALUE) CloseHandle(handle->file);
	if (handle->find != INVALID_HANDLE_VALUE) FindClose(handle->find);
	free(handle->directory);
	memset(handle, 0, sizeof(*handle));
}

static struct sftp_handle *read_handle(struct sftp_reader *reader,
		enum sftp_handle_kind required) {
	const unsigned char *value;
	uint32_t length;
	uint32_t index;
	uint32_t generation;
	struct sftp_handle *handle;
	if (!reader_string_view(reader, &value, &length) || length != 8) return NULL;
	index = load_u32(value);
	generation = load_u32(value + 4);
	if (index >= SFTP_HANDLE_COUNT) return NULL;
	handle = &sftp_handles[index];
	if (handle->kind == SFTP_HANDLE_NONE || handle->generation != generation ||
		(required != SFTP_HANDLE_NONE && handle->kind != required)) return NULL;
	return handle;
}

static int send_handle(HANDLE output, uint32_t id, uint32_t index,
		const struct sftp_handle *handle) {
	unsigned char token[8];
	struct sftp_builder builder;
	store_u32(token, index);
	store_u32(token + 4, handle->generation);
	builder_begin(&builder, SSH_FXP_HANDLE);
	builder_u32(&builder, id);
	builder_string_length(&builder, token, sizeof(token));
	return builder_send(&builder, output);
}

static int apply_attrs_handle(HANDLE file, const struct sftp_attrs *attrs) {
	if (attrs->flags & SSH_FILEXFER_ATTR_SIZE) {
		LARGE_INTEGER position;
		position.QuadPart = attrs->size;
		if (!SetFilePointerEx(file, position, NULL, FILE_BEGIN) || !SetEndOfFile(file)) return 0;
	}
	if (attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME) {
		FILETIME access_time = unix_to_filetime(attrs->atime);
		FILETIME write_time = unix_to_filetime(attrs->mtime);
		if (!SetFileTime(file, NULL, &access_time, &write_time)) return 0;
	}
	return 1;
}

static int apply_attrs_path(const wchar_t *path, const struct sftp_attrs *attrs) {
	HANDLE file;
	DWORD attributes = GetFileAttributesW(path);
	DWORD flags = (attributes != INVALID_FILE_ATTRIBUTES &&
		(attributes & FILE_ATTRIBUTE_DIRECTORY)) ? FILE_FLAG_BACKUP_SEMANTICS : 0;
	file = CreateFileW(path, FILE_WRITE_ATTRIBUTES |
		((attrs->flags & SSH_FILEXFER_ATTR_SIZE) ? GENERIC_WRITE : 0),
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, flags, NULL);
	if (file == INVALID_HANDLE_VALUE && (attrs->flags &
		(SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_ACMODTIME))) return 0;
	if (file != INVALID_HANDLE_VALUE) {
		if (!apply_attrs_handle(file, attrs)) {
			CloseHandle(file);
			return 0;
		}
		CloseHandle(file);
	}
	if ((attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS) &&
		attributes != INVALID_FILE_ATTRIBUTES) {
		if (attrs->permissions & 0222U) attributes &= ~FILE_ATTRIBUTE_READONLY;
		else attributes |= FILE_ATTRIBUTE_READONLY;
		if (!SetFileAttributesW(path, attributes)) return 0;
	}
	return 1;
}

static int handle_open(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	char *path_utf8 = reader_string(reader);
	wchar_t *path = NULL;
	uint32_t pflags;
	struct sftp_attrs attrs;
	DWORD access = 0;
	DWORD creation = OPEN_EXISTING;
	HANDLE file = INVALID_HANDLE_VALUE;
	struct sftp_handle *handle = NULL;
	uint32_t index;
	uint32_t status;
	int result;
	if (!path_utf8 || !reader_u32(reader, &pflags) || !reader_attrs(reader, &attrs)) {
		free(path_utf8);
		return send_status(output, id, SSH_FX_BAD_MESSAGE);
	}
	path = utf8_to_full_path(path_utf8);
	free(path_utf8);
	if (!path) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	if (pflags & SSH_FXF_READ) access |= GENERIC_READ;
	if (pflags & (SSH_FXF_WRITE | SSH_FXF_APPEND)) access |= GENERIC_WRITE;
	if (!access) access = GENERIC_READ;
	if ((pflags & SSH_FXF_CREAT) && (pflags & SSH_FXF_EXCL)) creation = CREATE_NEW;
	else if ((pflags & SSH_FXF_CREAT) && (pflags & SSH_FXF_TRUNC)) creation = CREATE_ALWAYS;
	else if (pflags & SSH_FXF_CREAT) creation = OPEN_ALWAYS;
	else if (pflags & SSH_FXF_TRUNC) creation = TRUNCATE_EXISTING;
	file = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE |
		FILE_SHARE_DELETE, NULL, creation, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		status = status_from_error(GetLastError());
		free(path);
		return send_status(output, id, status);
	}
	handle = allocate_handle(SFTP_HANDLE_FILE, &index);
	if (!handle) {
		CloseHandle(file);
		free(path);
		return send_status(output, id, SSH_FX_FAILURE);
	}
	handle->file = file;
	if (!apply_attrs_handle(file, &attrs)) {
		status = status_from_error(GetLastError());
		release_handle(handle);
		free(path);
		return send_status(output, id, status);
	}
	if (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) apply_attrs_path(path, &attrs);
	free(path);
	result = send_handle(output, id, index, handle);
	return result;
}

static int handle_close(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	struct sftp_handle *handle = read_handle(reader, SFTP_HANDLE_NONE);
	if (!handle) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	release_handle(handle);
	return send_status(output, id, SSH_FX_OK);
}

static int handle_read(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	struct sftp_handle *handle = read_handle(reader, SFTP_HANDLE_FILE);
	uint64_t offset;
	uint32_t requested;
	unsigned char *data;
	DWORD count = 0;
	LARGE_INTEGER position;
	struct sftp_builder builder;
	if (!handle || !reader_u64(reader, &offset) || !reader_u32(reader, &requested))
		return send_status(output, id, SSH_FX_BAD_MESSAGE);
	if (requested > SFTP_MAX_IO) requested = SFTP_MAX_IO;
	data = malloc(requested ? requested : 1);
	if (!data) return send_status(output, id, SSH_FX_FAILURE);
	position.QuadPart = offset;
	if (!SetFilePointerEx(handle->file, position, NULL, FILE_BEGIN) ||
		!ReadFile(handle->file, data, requested, &count, NULL)) {
		uint32_t status = status_from_error(GetLastError());
		free(data);
		return send_status(output, id, status);
	}
	if (count == 0) {
		free(data);
		return send_status(output, id, SSH_FX_EOF);
	}
	builder_begin(&builder, SSH_FXP_DATA);
	builder_u32(&builder, id);
	builder_string_length(&builder, data, count);
	free(data);
	return builder_send(&builder, output);
}

static int handle_write(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	struct sftp_handle *handle = read_handle(reader, SFTP_HANDLE_FILE);
	uint64_t offset;
	const unsigned char *data;
	uint32_t length;
	DWORD written = 0;
	LARGE_INTEGER position;
	if (!handle || !reader_u64(reader, &offset) ||
		!reader_string_view(reader, &data, &length) || length > SFTP_MAX_IO)
		return send_status(output, id, SSH_FX_BAD_MESSAGE);
	position.QuadPart = offset;
	if (!SetFilePointerEx(handle->file, position, NULL, FILE_BEGIN) ||
		!WriteFile(handle->file, data, length, &written, NULL) || written != length)
		return send_status(output, id, status_from_error(GetLastError()));
	return send_status(output, id, SSH_FX_OK);
}

static int handle_stat_path(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	char *path_utf8 = reader_string(reader);
	wchar_t *path;
	struct sftp_builder builder;
	DWORD error;
	if (!path_utf8) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	path = utf8_to_full_path(path_utf8);
	free(path_utf8);
	if (!path) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	builder_begin(&builder, SSH_FXP_ATTRS);
	builder_u32(&builder, id);
	if (!builder_attrs_path(&builder, path)) {
		error = GetLastError();
		free(builder.data);
		free(path);
		return send_status(output, id, status_from_error(error));
	}
	free(path);
	return builder_send(&builder, output);
}

static int handle_fstat(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	struct sftp_handle *handle = read_handle(reader, SFTP_HANDLE_FILE);
	struct sftp_builder builder;
	DWORD error;
	if (!handle) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	builder_begin(&builder, SSH_FXP_ATTRS);
	builder_u32(&builder, id);
	if (!builder_attrs_handle(&builder, handle->file)) {
		error = GetLastError();
		free(builder.data);
		return send_status(output, id, status_from_error(error));
	}
	return builder_send(&builder, output);
}

static int handle_setstat(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	char *path_utf8 = reader_string(reader);
	wchar_t *path;
	struct sftp_attrs attrs;
	DWORD error;
	if (!path_utf8 || !reader_attrs(reader, &attrs)) {
		free(path_utf8);
		return send_status(output, id, SSH_FX_BAD_MESSAGE);
	}
	path = utf8_to_full_path(path_utf8);
	free(path_utf8);
	if (!path) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	if (!apply_attrs_path(path, &attrs)) {
		error = GetLastError();
		free(path);
		return send_status(output, id, status_from_error(error));
	}
	free(path);
	return send_status(output, id, SSH_FX_OK);
}

static int handle_fsetstat(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	struct sftp_handle *handle = read_handle(reader, SFTP_HANDLE_FILE);
	struct sftp_attrs attrs;
	if (!handle || !reader_attrs(reader, &attrs))
		return send_status(output, id, SSH_FX_BAD_MESSAGE);
	if (!apply_attrs_handle(handle->file, &attrs))
		return send_status(output, id, status_from_error(GetLastError()));
	return send_status(output, id, SSH_FX_OK);
}

static int handle_opendir(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	char *path_utf8 = reader_string(reader);
	wchar_t *path;
	wchar_t *pattern;
	size_t path_length;
	DWORD attributes;
	struct sftp_handle *handle;
	uint32_t index;
	if (!path_utf8) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	path = utf8_to_full_path(path_utf8);
	free(path_utf8);
	if (!path) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	attributes = GetFileAttributesW(path);
	if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
		uint32_t status = attributes == INVALID_FILE_ATTRIBUTES
			? status_from_error(GetLastError()) : SSH_FX_FAILURE;
		free(path);
		return send_status(output, id, status);
	}
	handle = allocate_handle(SFTP_HANDLE_DIRECTORY, &index);
	if (!handle) {
		free(path);
		return send_status(output, id, SSH_FX_FAILURE);
	}
	handle->directory = path;
	path_length = wcslen(path);
	pattern = malloc((path_length + 3) * sizeof(*pattern));
	if (!pattern) {
		release_handle(handle);
		return send_status(output, id, SSH_FX_FAILURE);
	}
	wcscpy(pattern, path);
	if (path_length && path[path_length - 1] != L'\\') wcscat(pattern, L"\\");
	wcscat(pattern, L"*");
	handle->find = FindFirstFileW(pattern, &handle->find_data);
	free(pattern);
	if (handle->find == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		if (error != ERROR_FILE_NOT_FOUND) {
			release_handle(handle);
			return send_status(output, id, status_from_error(error));
		}
	} else {
		handle->have_find_data = 1;
	}
	return send_handle(output, id, index, handle);
}

static int handle_readdir(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	struct sftp_handle *handle = read_handle(reader, SFTP_HANDLE_DIRECTORY);
	struct sftp_builder builder;
	size_t count_position;
	uint32_t count = 0;
	if (!handle) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	builder_begin(&builder, SSH_FXP_NAME);
	builder_u32(&builder, id);
	count_position = builder.length;
	builder_u32(&builder, 0);
	while (handle->have_find_data && count < 64) {
		WIN32_FIND_DATAW *data = &handle->find_data;
		if (wcscmp(data->cFileName, L".") != 0 && wcscmp(data->cFileName, L"..") != 0) {
			char *name = wide_path_to_utf8(data->cFileName);
			if (!name) {
				free(builder.data);
				return send_status(output, id, SSH_FX_FAILURE);
			}
			builder_string(&builder, name);
			builder_string(&builder, name);
			builder_attrs_find(&builder, data);
			free(name);
			if (builder.failed) break;
			count++;
		}
		if (!FindNextFileW(handle->find, &handle->find_data)) {
			handle->have_find_data = 0;
			FindClose(handle->find);
			handle->find = INVALID_HANDLE_VALUE;
		}
	}
	if (count == 0) {
		free(builder.data);
		return send_status(output, id, SSH_FX_EOF);
	}
	store_u32(builder.data + count_position, count);
	return builder_send(&builder, output);
}

static int handle_realpath(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	char *path_utf8 = reader_string(reader);
	wchar_t *path;
	char *canonical;
	struct sftp_builder builder;
	if (!path_utf8) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	path = utf8_to_full_path(path_utf8);
	free(path_utf8);
	if (!path) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	canonical = wide_path_to_utf8(path);
	if (!canonical) {
		free(path);
		return send_status(output, id, SSH_FX_FAILURE);
	}
	builder_begin(&builder, SSH_FXP_NAME);
	builder_u32(&builder, id);
	builder_u32(&builder, 1);
	builder_string(&builder, canonical);
	builder_string(&builder, canonical);
	if (!builder_attrs_path(&builder, path)) builder_u32(&builder, 0);
	free(canonical);
	free(path);
	return builder_send(&builder, output);
}

static int handle_single_path(struct sftp_reader *reader, HANDLE output,
		uint32_t id, unsigned char type) {
	char *path_utf8 = reader_string(reader);
	wchar_t *path;
	struct sftp_attrs attrs;
	BOOL success = FALSE;
	DWORD error;
	if (!path_utf8) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	path = utf8_to_full_path(path_utf8);
	free(path_utf8);
	if (!path) return send_status(output, id, SSH_FX_BAD_MESSAGE);
	if (type == SSH_FXP_REMOVE) success = DeleteFileW(path);
	else if (type == SSH_FXP_RMDIR) success = RemoveDirectoryW(path);
	else if (type == SSH_FXP_MKDIR) {
		if (!reader_attrs(reader, &attrs)) {
			free(path);
			return send_status(output, id, SSH_FX_BAD_MESSAGE);
		}
		success = CreateDirectoryW(path, NULL);
		if (success) apply_attrs_path(path, &attrs);
	}
	if (!success) {
		error = GetLastError();
		free(path);
		return send_status(output, id, status_from_error(error));
	}
	free(path);
	return send_status(output, id, SSH_FX_OK);
}

static int handle_rename(struct sftp_reader *reader, HANDLE output, uint32_t id) {
	char *old_utf8 = reader_string(reader);
	char *new_utf8 = reader_string(reader);
	wchar_t *old_path;
	wchar_t *new_path;
	DWORD error;
	if (!old_utf8 || !new_utf8) {
		free(old_utf8);
		free(new_utf8);
		return send_status(output, id, SSH_FX_BAD_MESSAGE);
	}
	old_path = utf8_to_full_path(old_utf8);
	new_path = utf8_to_full_path(new_utf8);
	free(old_utf8);
	free(new_utf8);
	if (!old_path || !new_path) {
		free(old_path);
		free(new_path);
		return send_status(output, id, SSH_FX_BAD_MESSAGE);
	}
	if (!MoveFileExW(old_path, new_path, MOVEFILE_REPLACE_EXISTING |
		MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
		error = GetLastError();
		free(old_path);
		free(new_path);
		return send_status(output, id, status_from_error(error));
	}
	free(old_path);
	free(new_path);
	return send_status(output, id, SSH_FX_OK);
}

static int dispatch_request(unsigned char type, struct sftp_reader *reader,
		HANDLE output) {
	uint32_t id;
	if (!reader_u32(reader, &id)) return send_status(output, 0, SSH_FX_BAD_MESSAGE);
	switch (type) {
		case SSH_FXP_OPEN: return handle_open(reader, output, id);
		case SSH_FXP_CLOSE: return handle_close(reader, output, id);
		case SSH_FXP_READ: return handle_read(reader, output, id);
		case SSH_FXP_WRITE: return handle_write(reader, output, id);
		case SSH_FXP_LSTAT:
		case SSH_FXP_STAT: return handle_stat_path(reader, output, id);
		case SSH_FXP_FSTAT: return handle_fstat(reader, output, id);
		case SSH_FXP_SETSTAT: return handle_setstat(reader, output, id);
		case SSH_FXP_FSETSTAT: return handle_fsetstat(reader, output, id);
		case SSH_FXP_OPENDIR: return handle_opendir(reader, output, id);
		case SSH_FXP_READDIR: return handle_readdir(reader, output, id);
		case SSH_FXP_REMOVE:
		case SSH_FXP_MKDIR:
		case SSH_FXP_RMDIR: return handle_single_path(reader, output, id, type);
		case SSH_FXP_REALPATH: return handle_realpath(reader, output, id);
		case SSH_FXP_RENAME: return handle_rename(reader, output, id);
		case SSH_FXP_READLINK:
		case SSH_FXP_SYMLINK:
		case SSH_FXP_EXTENDED:
		default: return send_status(output, id, SSH_FX_OP_UNSUPPORTED);
	}
}

static void close_all_handles(void) {
	uint32_t index;
	for (index = 0; index < SFTP_HANDLE_COUNT; index++) {
		if (sftp_handles[index].kind != SFTP_HANDLE_NONE)
			release_handle(&sftp_handles[index]);
	}
}

int dropbear_win_sftp_main(void) {
	HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
	HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	unsigned char header[4];
	int initialized = 0;
	_setmode(STDIN_FILENO, _O_BINARY);
	_setmode(STDOUT_FILENO, _O_BINARY);
	_setmode(STDERR_FILENO, _O_BINARY);

	for (;;) {
		uint32_t length;
		unsigned char *packet;
		unsigned char type;
		struct sftp_reader reader;
		if (!read_exact(input, header, sizeof(header))) break;
		length = load_u32(header);
		if (length < 1 || length > SFTP_MAX_PACKET) break;
		packet = malloc(length);
		if (!packet || !read_exact(input, packet, length)) {
			free(packet);
			break;
		}
		type = packet[0];
		reader.data = packet + 1;
		reader.length = length - 1;
		reader.position = 0;
		if (!initialized) {
			uint32_t requested_version;
			struct sftp_builder builder;
			if (type != SSH_FXP_INIT || !reader_u32(&reader, &requested_version)) {
				free(packet);
				break;
			}
			(void)requested_version;
			builder_begin(&builder, SSH_FXP_VERSION);
			builder_u32(&builder, 3);
			initialized = builder_send(&builder, output);
			free(packet);
			if (!initialized) break;
			continue;
		}
		if (!dispatch_request(type, &reader, output)) {
			free(packet);
			break;
		}
		free(packet);
	}
	close_all_handles();
	return 0;
}

#else

int dropbear_win_sftp_main(void) {
	return 1;
}

#endif
