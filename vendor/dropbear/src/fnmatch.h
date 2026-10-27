#ifndef DROPBEAR_WIN_FNMATCH_H_
#define DROPBEAR_WIN_FNMATCH_H_

#define FNM_NOMATCH 1
int fnmatch(const char *pattern, const char *string, int flags);

#endif
