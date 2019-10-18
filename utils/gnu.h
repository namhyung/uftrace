#ifndef GNU_H
#define GNU_H

#include <dirent.h>
#include <string.h>
#include "posix.h"

#ifndef HAVE_STRVERSCMP
static inline int strverscmp(const char *a, const char *b)
{
	int a_int = 0;
	int b_int = 0;
	size_t a_len = strlen(a);
	size_t b_len = strlen(b);
	size_t a_digitstart = a_len;
	size_t b_digitstart = b_len;
	while(isdigit(a[a_digitstart - 1]) && a_digitstart != 0)
		--a_digitstart;
	while(isdigit(b[b_digitstart - 1]) && b_digitstart != 0)
		--b_digitstart;
	for(size_t i = a_digitstart; i != a_len; ++i) {
		if(isdigit(a[i]))
			a_int = a_int * 10 + (a[i] - '0');
	}
	for(size_t i = b_digitstart; i != b_len; ++i) {
		if(isdigit(b[i]))
			b_int = b_int * 10 + (b[i] - '0');
	}
	int diff = a_int - b_int;
	if(!diff)
		return strcoll(a, b);
	return diff;
}
#endif

#ifndef HAVE_VERSIONSORT
static inline int versionsort(const struct dirent **a, const struct dirent **b)
{
	return strverscmp((*a)->d_name, (*b)->d_name);
}
#endif

#endif /* GNU_H */
