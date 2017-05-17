#include <stdbool.h>

void ctf_init(char* host, char* exename);

void ctf_flush();

void ctf_set_cpu(int cpu);

void ctf_append_event(int tid,
                      int pid,
                      uint64_t timestamp,
                      uint64_t func_addr,
                      char* func_name,
                      bool is_entry);
