#include "includes.h"
#include "session.h"
#include "dbutil.h"
#include "curve25519.h"
#include "ed25519.h"
#include "win-account.h"

#define ACCOUNT_ITERATIONS 100000
#define SHA256_BLOCK 64

/* Unauthenticated clients can start connections freely, and every password
 * attempt costs a full PBKDF2 derivation. Cap how many derivations run at the
 * same time across all connection processes, so a flood cannot turn the whole
 * machine into password-verification CPU.
 *
 * The cap uses one named mutex per slot rather than a counting semaphore: a
 * connection process killed mid-derivation (port takeover, restart, crash)
 * would permanently consume a semaphore permit, while a mutex is released by
 * the kernel as abandoned and the next waiter takes it over. The names live in
 * the session namespace, which every child of this server shares. */
#define VERIFY_GATE_NAME "Local\\DropbearWin-pbkdf2-%d"
/* Waits are bounded. Reaching the bound means something is very wrong, so the
 * attempt fails instead of joining an unbounded queue of expensive checks. */
#define VERIFY_GATE_WAIT_MS 30000
#define VERIFY_GATE_MAX_PERMITS 16
#define VERIFY_GATE_DEFAULT_MAX_PERMITS 3
static HANDLE verify_gate_slots[VERIFY_GATE_MAX_PERMITS];
static int verify_gate_slot_count;
static int verify_gate_checked;

static char data_dir[MAX_PATH];
static char account_file[MAX_PATH];
static char hostkey_file[MAX_PATH];
static char pidfile_file[MAX_PATH];

static int create_data_dir(const char *path) {
	return CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

/* The installed service stores its state outside Program Files. XP uses the
 * All Users application-data directory; later Windows provides ProgramData. */
int dropbear_win_installed_data_path(char *path, size_t size) {
	const char *root = getenv("ProgramData");
	const char *suffix = "\\DropbearWin";
	int written;
	if (!root || !root[0]) {
		root = getenv("ALLUSERSPROFILE");
		suffix = "\\Application Data\\DropbearWin";
	}
	if (!root || !root[0]) return 0;
	written = snprintf(path, size, "%s%s", root, suffix);
	return written > 0 && (size_t)written < size;
}

static int set_data_paths(void) {
	char executable[MAX_PATH];
	char *separator;
	const char *inherited = getenv("DROPBEAR_WIN_DATA_DIR");
	const char *inherited_account;
	if (data_dir[0] && account_file[0] && hostkey_file[0] && pidfile_file[0]) return 1;
	if (inherited && inherited[0] && strlen(inherited) < sizeof(data_dir)) {
		strcpy(data_dir, inherited);
		if (!create_data_dir(data_dir)) return 0;
	} else {
		if (!GetModuleFileNameA(NULL, executable, sizeof(executable))) return 0;
		separator = strrchr(executable, '\\');
		if (!separator) separator = strrchr(executable, '/');
		if (!separator) return 0;
		*separator = '\0';
		if (snprintf(data_dir, sizeof(data_dir), "%s\\dropbear-win-data", executable)
				>= (int)sizeof(data_dir)) return 0;
		/* The marker is written only after the installer copied and checked the
		 * account and host key. Older portable/service deployments keep their
		 * original adjacent data until explicitly migrated. */
		{
			char marker[MAX_PATH];
			if (snprintf(marker, sizeof(marker), "%s\\dropbear-win.installed", executable)
					>= (int)sizeof(marker)) return 0;
			if (GetFileAttributesA(marker) != INVALID_FILE_ATTRIBUTES) {
				if (!dropbear_win_installed_data_path(data_dir, sizeof(data_dir)) ||
						!create_data_dir(data_dir)) return 0;
			} else if (!create_data_dir(data_dir)) {
				const char *program_data = getenv("ProgramData");
				const char *all_users = getenv("ALLUSERSPROFILE");
				const char *temporary = getenv("TEMP");
				if (program_data && snprintf(data_dir, sizeof(data_dir),
						"%s\\DropbearWin", program_data) < (int)sizeof(data_dir) &&
						create_data_dir(data_dir)) {
					/* Windows Vista and later fallback. */
				} else if (all_users && snprintf(data_dir, sizeof(data_dir),
						"%s\\Application Data\\DropbearWin", all_users) < (int)sizeof(data_dir) &&
						create_data_dir(data_dir)) {
					/* Windows XP/Server 2003 fallback. */
				} else if (temporary && snprintf(data_dir, sizeof(data_dir),
						"%s\\DropbearWin", temporary) < (int)sizeof(data_dir) &&
						create_data_dir(data_dir)) {
					/* WinPE fallback when persistent locations are read-only. */
				} else {
					return 0;
				}
			}
		}
	}
	inherited_account = getenv("DROPBEAR_WIN_ACCOUNT_FILE");
	if (inherited_account && inherited_account[0] &&
			strlen(inherited_account) < sizeof(account_file)) {
		strcpy(account_file, inherited_account);
	} else if (snprintf(account_file, sizeof(account_file), "%s\\account.conf", data_dir)
			>= (int)sizeof(account_file)) {
		return 0;
	}
	if (
		snprintf(hostkey_file, sizeof(hostkey_file), "%s\\hostkey_ed25519", data_dir)
			>= (int)sizeof(hostkey_file) ||
		snprintf(pidfile_file, sizeof(pidfile_file), "%s\\dropbear.pid", data_dir)
			>= (int)sizeof(pidfile_file)) return 0;
	if (!SetEnvironmentVariableA("DROPBEAR_WIN_DATA_DIR", data_dir) ||
			!SetEnvironmentVariableA("DROPBEAR_WIN_ACCOUNT_FILE", account_file)) return 0;
	return 1;
}

static int account_path(char *out, size_t outlen) {
	if (!account_file[0] && !set_data_paths()) return 0;
	if (strlen(account_file) >= outlen) return 0;
	strcpy(out, account_file);
	return 1;
}

const char *dropbear_win_account_file_path(void) {
	if (!account_file[0] && !set_data_paths()) return NULL;
	return account_file;
}

int dropbear_win_custom_auth_enabled(void) {
	char path[MAX_PATH];
	return account_path(path, sizeof(path));
}

const char *dropbear_win_hostkey_path(void) {
	if (!hostkey_file[0] && !set_data_paths()) return "dropbear-win-hostkey";
	return hostkey_file;
}

const char *dropbear_win_pidfile_path(void) {
	if (!pidfile_file[0] && !set_data_paths()) return "dropbear-win.pid";
	return pidfile_file;
}

int dropbear_win_ed25519_key_valid(const struct dropbear_ED25519_Key *key) {
	static const unsigned char challenge[] =
		"dropbear-win ed25519 hostkey self-test v1";
	unsigned char signature[64];
	unsigned long signature_length = sizeof(signature);
	int valid;

	if (!key || !dropbear_win_ed25519_selftest()) return 0;
	dropbear_ed25519_sign(challenge, sizeof(challenge) - 1,
		signature, &signature_length, key->priv, key->pub);
	valid = signature_length == sizeof(signature) &&
		dropbear_ed25519_verify(challenge, sizeof(challenge) - 1,
			signature, signature_length, key->pub) == 0;
	m_burn(signature, sizeof(signature));
	return valid;
}

int dropbear_win_ed25519_selftest(void) {
	static const unsigned char private_key[32] = {
		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
		0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
		0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
		0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
	};
	static const unsigned char public_key[32] = {
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
	};
	static const unsigned char expected_signature[64] = {
		0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
		0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
		0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
		0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
		0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
		0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
		0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
		0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
	};
	static const unsigned char empty_message[1] = {0};
	static int result = -1;
	unsigned char signature[64];
	unsigned long signature_length = sizeof(signature);
	if (result >= 0) return result;
	dropbear_ed25519_sign(empty_message, 0, signature, &signature_length,
		private_key, public_key);
	result = signature_length == sizeof(signature) &&
		memcmp(signature, expected_signature, sizeof(signature)) == 0 &&
		dropbear_ed25519_verify(empty_message, 0, expected_signature,
			sizeof(expected_signature), public_key) == 0;
	m_burn(signature, sizeof(signature));
	return result;
}

int dropbear_win_hostkey_file_invalid(const char *path) {
	static const unsigned char prefix[] = {
		0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9',
		0, 0, 0, 64
	};
	unsigned char encoded[19 + 64];
	FILE *file;
	size_t count;
	int trailing;
	int invalid;

	if (!path || !set_data_paths() || _stricmp(path, hostkey_file) != 0 ||
			GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) return 0;
	file = fopen(path, "rb");
	if (!file) return 1;
	count = fread(encoded, 1, sizeof(encoded), file);
	trailing = fgetc(file);
	fclose(file);
	invalid = count != sizeof(encoded) || trailing != EOF ||
		memcmp(encoded, prefix, sizeof(prefix)) != 0;
	m_burn(encoded, sizeof(encoded));
	return invalid;
}

int dropbear_win_delete_hostkey(const char *path) {
	if (!path || !set_data_paths() || _stricmp(path, hostkey_file) != 0) return 0;
	return DeleteFileA(path) != 0;
}

const char *dropbear_win_shell(void) {
	static char shell[MAX_PATH];
	char system_dir[MAX_PATH];
	char windows_dir[MAX_PATH];
	const char *backend = getenv("DROPBEAR_WIN_SHELL");
	if (!backend || !backend[0] || strcmp(backend, "cmd") == 0) {
		if (!GetSystemDirectoryA(system_dir, sizeof(system_dir))) return "";
		snprintf(shell, sizeof(shell), "%s\\cmd.exe", system_dir);
		return shell;
	}
	if (strcmp(backend, "powershell") == 0 && GetWindowsDirectoryA(windows_dir, sizeof(windows_dir))) {
		snprintf(shell, sizeof(shell),
			"%s\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", windows_dir);
	}
	return shell;
}

const char *dropbear_win_data_dir(void) {
	if (!data_dir[0] && !set_data_paths()) return "unknown";
	return data_dir;
}

const char *dropbear_win_binary_architecture(void) {
#ifdef _WIN64
	return "x64";
#else
	return "x86";
#endif
}

const char *dropbear_win_compatibility_profile(void) {
#ifdef _WIN64
	return "NT 5.2+ / XP x64 SP2 / Server 2003 SP2";
#else
	return "NT 5.1+ / XP SP3 / WinPE 1.6";
#endif
}

int dropbear_win_account_name(char *username, size_t username_size) {
	char path[MAX_PATH];
	FILE *file;
	if (!username || username_size < 2 || !account_path(path, sizeof(path))) return 0;
	file = fopen(path, "rb");
	if (!file) return 0;
	if (!fgets(username, (int)username_size, file)) {
		fclose(file);
		return 0;
	}
	fclose(file);
	username[strcspn(username, "\r\n")] = '\0';
	return username[0] != '\0';
}

static int from_hex(const char *text, unsigned char *output, unsigned int outputlen) {
	unsigned int i;
	for (i = 0; i < outputlen; i++) {
		unsigned int value;
		if (sscanf(text + i * 2, "%2x", &value) != 1) return 0;
		output[i] = (unsigned char)value;
	}
	return text[outputlen * 2] == '\0';
}

static void to_hex(const unsigned char *input, unsigned int inputlen, char *output) {
	static const char digits[] = "0123456789abcdef";
	unsigned int i;
	for (i = 0; i < inputlen; i++) {
		output[i * 2] = digits[input[i] >> 4];
		output[i * 2 + 1] = digits[input[i] & 15];
	}
	output[inputlen * 2] = '\0';
}

/* PBKDF2-HMAC-SHA256 (RFC 8018), single 32 byte output block, byte-identical
 * to hashlib.pbkdf2_hmac and to the format written by first-run setup.
 * The keyed inner and outer SHA-256 states are built once and copied for each
 * round, so 100000 iterations no longer repeat the HMAC key setup 100000
 * times. */
static int derive_password(const char *password, unsigned int passwordlen,
		const unsigned char salt[32], unsigned long iterations,
		unsigned char output[32]) {
	hash_state inner_base, outer_base, state;
	hash_state key_hash;
	unsigned char key_pad[SHA256_BLOCK], inner_pad[SHA256_BLOCK];
	unsigned char outer_pad[SHA256_BLOCK], counter[4] = {0, 0, 0, 1};
	unsigned char block[32], digest[32];
	unsigned long round;
	unsigned int i;
	int result = 0;

	memset(key_pad, 0, sizeof(key_pad));
	if (passwordlen > sizeof(key_pad)) {
		if (sha256_init(&key_hash) != CRYPT_OK ||
				sha256_process(&key_hash, (const unsigned char *)password,
					passwordlen) != CRYPT_OK ||
				sha256_done(&key_hash, key_pad) != CRYPT_OK) goto out;
	} else if (passwordlen) {
		memcpy(key_pad, password, passwordlen);
	}
	for (i = 0; i < sizeof(key_pad); i++) {
		inner_pad[i] = key_pad[i] ^ 0x36;
		outer_pad[i] = key_pad[i] ^ 0x5c;
	}
	if (sha256_init(&inner_base) != CRYPT_OK ||
			sha256_process(&inner_base, inner_pad, sizeof(inner_pad)) != CRYPT_OK ||
			sha256_init(&outer_base) != CRYPT_OK ||
			sha256_process(&outer_base, outer_pad, sizeof(outer_pad)) != CRYPT_OK) {
		goto out;
	}

	/* U1 = HMAC(password, salt || INT_32_BE(1)) */
	state = inner_base;
	if (sha256_process(&state, salt, 32) != CRYPT_OK ||
			sha256_process(&state, counter, sizeof(counter)) != CRYPT_OK ||
			sha256_done(&state, digest) != CRYPT_OK) goto out;
	state = outer_base;
	if (sha256_process(&state, digest, sizeof(digest)) != CRYPT_OK ||
			sha256_done(&state, block) != CRYPT_OK) goto out;
	memcpy(output, block, sizeof(block));

	for (round = 1; round < iterations; round++) {
		state = inner_base;
		if (sha256_process(&state, block, sizeof(block)) != CRYPT_OK ||
				sha256_done(&state, digest) != CRYPT_OK) goto out;
		state = outer_base;
		if (sha256_process(&state, digest, sizeof(digest)) != CRYPT_OK ||
				sha256_done(&state, block) != CRYPT_OK) goto out;
		for (i = 0; i < sizeof(block); i++) output[i] ^= block[i];
	}
	result = 1;

out:
	m_burn(key_pad, sizeof(key_pad));
	m_burn(inner_pad, sizeof(inner_pad));
	m_burn(outer_pad, sizeof(outer_pad));
	m_burn(block, sizeof(block));
	m_burn(digest, sizeof(digest));
	m_burn(&key_hash, sizeof(key_hash));
	m_burn(&inner_base, sizeof(inner_base));
	m_burn(&outer_base, sizeof(outer_base));
	m_burn(&state, sizeof(state));
	return result;
}

/* Permits default to a quarter of the available processors, between one and
 * three. DROPBEAR_WIN_KDF_CONCURRENCY overrides it for tuning and for tests. */
static int verify_gate_permits(void) {
	const char *configured = getenv("DROPBEAR_WIN_KDF_CONCURRENCY");
	SYSTEM_INFO info;
	char *end = NULL;
	unsigned long value;
	int permits;

	if (configured && configured[0]) {
		value = strtoul(configured, &end, 10);
		if (end && *end == '\0' && value >= 1 && value <= VERIFY_GATE_MAX_PERMITS) return (int)value;
	}
	GetSystemInfo(&info);
	permits = (int)(info.dwNumberOfProcessors / 4);
	if (permits < 1) permits = 1;
	if (permits > VERIFY_GATE_DEFAULT_MAX_PERMITS) permits = VERIFY_GATE_DEFAULT_MAX_PERMITS;
	return permits;
}

static int verify_gate_open(void) {
	char name[64];
	int permits;
	int index;
	if (verify_gate_checked) return verify_gate_slot_count;
	verify_gate_checked = 1;
	permits = verify_gate_permits();
	for (index = 0; index < permits; index++) {
		if (snprintf(name, sizeof(name), VERIFY_GATE_NAME, index) >= (int)sizeof(name)) break;
		verify_gate_slots[index] = CreateMutexA(NULL, FALSE, name);
		if (!verify_gate_slots[index]) break;
	}
	/* A missing gate only removes the throttle; it must never block logins. */
	verify_gate_slot_count = index;
	return verify_gate_slot_count;
}

static int read_line(char *buffer, unsigned int size) {
	if (!fgets(buffer, size, stdin)) return 0;
	buffer[strcspn(buffer, "\r\n")] = '\0';
	return buffer[0] != '\0';
}

static int read_secret(const char *prompt, char *buffer, unsigned int size) {
	fputs(prompt, stdout);
	fflush(stdout);
	return read_line(buffer, size);
}

static int existing_account_valid(void) {
	char user[128], hash[512], *end, *salt, *digest;
	unsigned long iterations;
	FILE *file = fopen(account_file, "rb");
	int ok = file && fgets(user, sizeof(user), file) && fgets(hash, sizeof(hash), file);
	if (file) fclose(file);
	if (!ok) return 0;
	user[strcspn(user, "\r\n")] = 0;
	hash[strcspn(hash, "\r\n")] = 0;
	if (!user[0] || strncmp(hash, "pbkdf2-sha256$", 14)) return 0;
	iterations = strtoul(hash + 14, &end, 10);
	if (end == hash + 14 || *end != '$' || iterations < 10000 || iterations > 2000000) return 0;
	salt = end + 1;
	digest = strchr(salt, '$');
	if (!digest || digest - salt != 64) return 0;
	*digest++ = 0;
	return strlen(digest) == 64 && strspn(salt, "0123456789abcdefABCDEF") == 64 &&
		strspn(digest, "0123456789abcdefABCDEF") == 64;
}

int dropbear_win_prepare(void) {
	char username[128], password[DROPBEAR_MAX_PASSWORD_LEN + 1];
	char confirm[DROPBEAR_MAX_PASSWORD_LEN + 1];
	unsigned char salt[32], hash[32];
	char salt_hex[65], hash_hex[65];
	FILE *file;
	const char *backend = getenv("DROPBEAR_WIN_SHELL");
	if (backend && backend[0] && strcmp(backend, "cmd") && strcmp(backend, "powershell")) {
		fputs("DROPBEAR_WIN_SHELL must be cmd or powershell.\n", stderr);
		return 0;
	}
	if (GetFileAttributesA(dropbear_win_shell()) == INVALID_FILE_ATTRIBUTES) {
		fputs("Selected Windows shell does not exist.\n", stderr);
		return 0;
	}
	if (!dropbear_win_ed25519_selftest()) {
		fputs("ED25519 RFC 8032 self-test failed.\n", stderr);
		return 0;
	}
	if (!set_data_paths()) return 0;
	if (GetFileAttributesA(account_file) != INVALID_FILE_ATTRIBUTES) {
		if (existing_account_valid()) return 1;
		fprintf(stderr, "Invalid or unreadable account configuration: %s\n", account_file);
		return 0;
	}
	if (dropbear_win_is_service()) {
		fputs("Service requires an existing account.conf; run interactive setup first.\n", stderr);
		return 0;
	}
	fputs("Dropbear for Windows first-run setup\nSSH username: ", stdout);
	fflush(stdout);
	if (!read_line(username, sizeof(username))) return 0;
	for (;;) {
		if (!read_secret("SSH password: ", password, sizeof(password)) ||
				!read_secret("Confirm password: ", confirm, sizeof(confirm))) {
			m_burn(password, sizeof(password));
			m_burn(confirm, sizeof(confirm));
			return 0;
		}
		if (strcmp(password, confirm) == 0) break;
		fputs("Passwords do not match. Please try again.\n", stderr);
		m_burn(password, sizeof(password));
		m_burn(confirm, sizeof(confirm));
	}
	if (dropbear_win_random(salt, sizeof(salt)) != 0 ||
			!derive_password(password, strlen(password), salt, ACCOUNT_ITERATIONS, hash)) {
		m_burn(password, sizeof(password));
		m_burn(confirm, sizeof(confirm));
		m_burn(hash, sizeof(hash));
		return 0;
	}
	to_hex(salt, sizeof(salt), salt_hex);
	to_hex(hash, sizeof(hash), hash_hex);
	file = fopen(account_file, "wb");
	if (!file) {
		m_burn(password, sizeof(password));
		m_burn(confirm, sizeof(confirm));
		m_burn(hash, sizeof(hash));
		return 0;
	}
	fprintf(file, "%s\npbkdf2-sha256$%d$%s$%s\n",
		username, ACCOUNT_ITERATIONS, salt_hex, hash_hex);
	fclose(file);
	m_burn(password, sizeof(password));
	m_burn(confirm, sizeof(confirm));
	m_burn(hash, sizeof(hash));
	fprintf(stdout, "Configuration created in %s\n", data_dir);
	return 1;
}

int dropbear_win_password_verify(const char *password, unsigned int passwordlen,
		const char *stored) {
	char copy[512];
	char *algorithm, *iterations_text, *salt_text, *hash_text;
	unsigned char salt[32], expected[32], actual[32];
	unsigned long iterations;
	DWORD waited;
	int slot = -1;
	int verified;
	int result;
	if (!stored || strlen(stored) >= sizeof(copy)) return 0;
	strcpy(copy, stored);
	algorithm = strtok(copy, "$");
	iterations_text = strtok(NULL, "$");
	salt_text = strtok(NULL, "$");
	hash_text = strtok(NULL, "$");
	if (!algorithm || !iterations_text || !salt_text || !hash_text ||
		strcmp(algorithm, "pbkdf2-sha256") != 0 || strlen(salt_text) != 64 ||
		strlen(hash_text) != 64) return 0;
	iterations = strtoul(iterations_text, NULL, 10);
	if (iterations < 10000 || iterations > 2000000 ||
		!from_hex(salt_text, salt, sizeof(salt)) ||
		!from_hex(hash_text, expected, sizeof(expected))) return 0;
	if (verify_gate_open() > 0) {
		waited = WaitForMultipleObjects((DWORD)verify_gate_slot_count,
			verify_gate_slots, FALSE, VERIFY_GATE_WAIT_MS);
		if (waited == WAIT_TIMEOUT) {
			dropbear_log(LOG_WARNING,
				"Password checks are busy with other attempts; failing this attempt");
			m_burn(expected, sizeof(expected));
			return 0;
		}
		/* WAIT_ABANDONED means a connection process died while checking a
		 * password; the slot is ours to use and release. */
		if (waited >= WAIT_OBJECT_0 && waited < WAIT_OBJECT_0 + verify_gate_slot_count) {
			slot = (int)(waited - WAIT_OBJECT_0);
		} else if (waited >= WAIT_ABANDONED_0 &&
				waited < WAIT_ABANDONED_0 + verify_gate_slot_count) {
			slot = (int)(waited - WAIT_ABANDONED_0);
		}
	}
	verified = derive_password(password, passwordlen, salt, iterations, actual);
	if (slot >= 0) ReleaseMutex(verify_gate_slots[slot]);
	m_burn(salt, sizeof(salt));
	if (!verified) {
		m_burn(actual, sizeof(actual));
		m_burn(expected, sizeof(expected));
		return 0;
	}
	result = constant_time_memcmp(actual, expected, sizeof(actual)) == 0;
	m_burn(actual, sizeof(actual));
	m_burn(expected, sizeof(expected));
	return result;
}

int dropbear_win_account_lookup(const char *username,
		uid_t *uid, gid_t *gid,
		char **name, char **dir, char **shell, char **passwd) {
	char path[MAX_PATH], stored_user[128], stored_hash[512], cwd[MAX_PATH];
	FILE *fp;
	if (!account_path(path, sizeof(path)) || !username || strlen(username) >= sizeof(stored_user)) return 0;
	fp = fopen(path, "rb");
	if (!fp || !fgets(stored_user, sizeof(stored_user), fp) ||
		!fgets(stored_hash, sizeof(stored_hash), fp)) {
		if (fp) fclose(fp);
		return 0;
	}
	fclose(fp);
	stored_user[strcspn(stored_user, "\r\n")] = '\0';
	stored_hash[strcspn(stored_hash, "\r\n")] = '\0';
	if (strcmp(username, stored_user) != 0 || stored_hash[0] == '\0') return 0;
	if (!getcwd(cwd, sizeof(cwd))) strcpy(cwd, ".");
	*uid = geteuid();
	*gid = getegid();
	*name = m_strdup(stored_user);
	*dir = m_strdup(cwd);
	*shell = m_strdup(dropbear_win_shell());
	*passwd = m_strdup(stored_hash);
	return 1;
}
