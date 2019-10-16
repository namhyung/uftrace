/* strndup.c
 *
 */

/* Written by Niels Möller <nisse@lysator.liu.se>
 *
 * This file is hereby placed in the public domain.
 */

#include <string.h>

void *
mempcpy (void *to, const void *from, size_t size)
{
  memcpy(to, from, size);
  return (char *) to + size;
}

