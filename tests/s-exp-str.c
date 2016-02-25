char *str_cat(char *d, char *s)
{
	char *p = d;

	while (*d)
		d++;

	while (*d++ = *s++)
		continue;

	return p;
}

char *str_cpy(char *d, char *s)
{
	char *p = d;

	while (*d++ = *s++)
		continue;

	return p;
}

char a[32];
char b[32];

int main(void)
{
	char *c;

	/*
	 * string arguments are aligned in 8-byte boundary including
	 * 2-byte length prefix so checking strings with length of
	 * 5, 6 and 7 will be enough.
	 */
	str_cpy(a, "hello");
	str_cpy(b, " world");
	c = str_cat(a, b);
	str_cpy(a, "goodbye");
	c = str_cat(a, b);

	return *c ? 0 : 1;
}
