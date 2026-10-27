#ifndef DROPBEAR_WIN_ACCOUNT_H
#define DROPBEAR_WIN_ACCOUNT_H

#include <sys/types.h>

struct dropbear_ED25519_Key;

int dropbear_win_account_lookup(const char *username,
		uid_t *uid, gid_t *gid,
		char **name, char **dir, char **shell, char **passwd);
int dropbear_win_custom_auth_enabled(void);
const char *dropbear_win_shell(void);
const char *dropbear_win_data_dir(void);
int dropbear_win_account_name(char *username, size_t username_size);
int dropbear_win_prepare(void);
int dropbear_win_ed25519_selftest(void);
const char *dropbear_win_hostkey_path(void);
const char *dropbear_win_pidfile_path(void);
const char *dropbear_win_binary_architecture(void);
const char *dropbear_win_compatibility_profile(void);
int dropbear_win_ed25519_key_valid(const struct dropbear_ED25519_Key *key);
int dropbear_win_hostkey_file_invalid(const char *path);
int dropbear_win_delete_hostkey(const char *path);
int dropbear_win_password_verify(const char *password, unsigned int passwordlen,
		const char *stored);

#endif
