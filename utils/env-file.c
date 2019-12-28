#include "utils/env-file.h"

#define ERROR_CREATE_FILE \
"Error occurred while create file.\n"

#define ERROR_OPEN_FILE \
"Error occurred while open file.\n"

#define ERROR_READ_FILE \
"Error occurred while read file.\n"

#define ERROR_WHILE_WRITE \
"Error occurred while write file.\n"				\
"[Trouble shooting]\n"						\
"Check a file named 'uftrace_environ_file' is existed "		\
"under '/tmp'.\n"


/*
 * create_env_file() & set_env_to_file() were used in uftrace.
 * open_env_file() & set_env_from_file() were used in libmcount.
 */
int create_env_file(void)
{
	int fd;

	fd = open(ENV_FILE, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0)
		pr_err(ERROR_CREATE_FILE);

	return fd;
}

/*
 * write a line to uftrace environment file with given argument fd.
 * a line contain key-value pair with separator '='.
 * like this,
 *
 * [example]
 * UFTRACE_PLTHOOK=1
 */
void set_env_to_file(int fd, char *key, const char *value)
{
	int res;
	char buf[256];

	snprintf(buf, sizeof(buf), "%s=%s\n", key, value);
	res = write(fd, buf, strlen(buf));

	if (res < 0)
		pr_err(ERROR_WHILE_WRITE);
}

int open_env_file(void)
{
	int fd;

	fd = open(ENV_FILE, O_RDONLY);
	if (fd < 0)
		pr_err(ERROR_OPEN_FILE);

	return fd;
}

void set_env_from_file(int fd)
{
	char key[1024];
	char val[1024];
	FILE *fp;

	fp = fdopen(fd, "r");
	if (fp == NULL)
		pr_err(ERROR_READ_FILE);
	else {
		while(fscanf(fp, "%[^=]%*c%s\n", key, val) != EOF) {
			pr_dbg("key : %s val : %s\n", key, val);
			setenv(key, val, 1);
		}
	}
}

#ifdef UNIT_TEST
TEST_CASE(env_file) {
	int fd;
	char *val;

	// UFTRACE SIDE
	fd = create_env_file();
	TEST_GE(fd, 0);
	set_env_to_file(fd, "TEST_ENVFILE", "TEST_ENVFILE");

	// LIBMCOUNT SIDE
	fd = open_env_file();
	set_env_from_file(fd);
	val = getenv("TEST_ENVFILE");
	TEST_STREQ(val, "TEST_ENVFILE");

	return TEST_OK;
}
#endif
