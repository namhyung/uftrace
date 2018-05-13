#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <inttypes.h>
#include "utils/utils.h"

#define ENV_FILE  "/tmp/uftrace_environ_file"

int create_env_file(void);
int open_env_file(void);
void set_env_to_file(int fd, char *key, const char *value);
void set_env_from_file(int fd);
