#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  cpu_set_t cpuset;
  int total_cpus;
  int c, cpu;

  total_cpus = sysconf(_SC_NPROCESSORS_ONLN);
  cpu = sched_getcpu();

  CPU_ZERO(&cpuset);
  for (c = 0; c < total_cpus; c++) {
    if (c != cpu)
      CPU_SET(c, &cpuset);
  }
  sched_setaffinity(0, sizeof(cpuset), &cpuset);

  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);
  sched_setaffinity(0, sizeof(cpuset), &cpuset);

  return 0;
}

