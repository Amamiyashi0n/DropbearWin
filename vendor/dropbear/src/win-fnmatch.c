#include "includes.h"
#include "fnmatch.h"

static int match_class(const char **pattern, unsigned char value) {
	const char *p = *pattern;
	int negate = 0;
	int matched = 0;
	if (*p == '!' || *p == '^') {
		negate = 1;
		p++;
	}
	while (*p && *p != ']') {
		unsigned char first = (unsigned char)*p++;
		if (first == '\\' && *p) first = (unsigned char)*p++;
		if (*p == '-' && p[1] && p[1] != ']') {
			unsigned char last;
			p++;
			last = (unsigned char)*p++;
			if (last == '\\' && *p) last = (unsigned char)*p++;
			if (value >= first && value <= last) matched = 1;
		} else if (value == first) {
			matched = 1;
		}
	}
	if (*p != ']') return -1;
	*pattern = p + 1;
	return negate ? !matched : matched;
}

static int match_pattern(const char *pattern, const char *string) {
	while (*pattern) {
		if (*pattern == '*') {
			while (*pattern == '*') pattern++;
			if (!*pattern) return 1;
			while (*string) {
				if (match_pattern(pattern, string)) return 1;
				string++;
			}
			return match_pattern(pattern, string);
		}
		if (!*string) return 0;
		if (*pattern == '?') {
			pattern++;
			string++;
			continue;
		}
		if (*pattern == '[') {
			int result;
			pattern++;
			result = match_class(&pattern, (unsigned char)*string++);
			if (result <= 0) return 0;
			continue;
		}
		if (*pattern == '\\' && pattern[1]) pattern++;
		if (*pattern++ != *string++) return 0;
	}
	return *string == '\0';
}

int fnmatch(const char *pattern, const char *string, int flags) {
	(void)flags;
	return match_pattern(pattern, string) ? 0 : FNM_NOMATCH;
}
