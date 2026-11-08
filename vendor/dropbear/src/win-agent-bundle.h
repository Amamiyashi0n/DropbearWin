#ifndef DROPBEAR_WIN_AGENT_BUNDLE_H
#define DROPBEAR_WIN_AGENT_BUNDLE_H

/* A transaction keeps the previous resources until service configuration succeeds. */
struct dropbear_win_bundle_transaction;
const char *dropbear_win_bundle_content(const char *name);
const wchar_t *dropbear_win_bundle_name(unsigned int index);
int dropbear_win_bundle_begin(const wchar_t *directory,
    struct dropbear_win_bundle_transaction **transaction);
int dropbear_win_bundle_finish(struct dropbear_win_bundle_transaction *transaction, int commit);
int dropbear_win_bundle_directory(wchar_t *directory, size_t size);
int dropbear_win_bundle_directory_utf8(char *directory, size_t size);
int dropbear_win_bundle_export(const char *directory);

#endif
