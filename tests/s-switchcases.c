#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void call0(void) {
    printf("call0\n");
}

void call1(char* p1) {
    printf("call1: %s\n", p1);
}

void call2(char* p1, char* p2) {
    printf("call2: %s %s\n", p1, p2);
}

void call3(char* p1, char* p2) {
    printf("call3: %s %s\n", p1, p2);
}

void call4(char* p1, char* p2) {
    printf("call4: %s %s\n", p1, p2);
}

void call5(char* p1, char* p2, char* p3) {
    printf("call5: %s %s %s\n", p1, p2, p3);
}

void call6(char* p1, char* p2) {
    printf("call6: %s %s\n", p1, p2);
}

void call_default(void) {
    printf("call_default\n");
}

Elf64_Shdr* elf64_find_section_header(const char* file_content, const char* req_section_name) {
    Elf64_Ehdr* header = (void*) file_content;

    int section_header_count = header->e_shnum;
    if (section_header_count == 0) {
        fprintf(stderr, "elf: no section found in file\n");
        return NULL;
    }

    int headers_offset = header->e_shoff;
    Elf64_Shdr* headers = (void*) &file_content[headers_offset];

    int names_section_header_index = header->e_shstrndx;
    Elf64_Shdr* names_section_header = (void*) &headers[names_section_header_index];
    const char* names_section = &file_content[names_section_header->sh_offset];

    for (int i = 0; i < section_header_count; i++) {
        Elf64_Shdr* section_header = &headers[i];
        const char* section_name = &names_section[section_header->sh_name];
        
        if (strcmp(section_name, req_section_name) == 0) {
            return section_header;
        }
    }

    return NULL;
}

void* elf64_get_first_symbol_addr(const char* file_content, regex_t* req_symbol_name) {
    Elf64_Shdr* strtab_header = elf64_find_section_header(file_content, ".strtab");
    if (strtab_header == NULL) {
        return NULL;
    }
    char* strtab = (char*) &file_content[strtab_header->sh_offset];

    Elf64_Shdr* symtab_header = elf64_find_section_header(file_content, ".symtab");
    if (symtab_header == NULL) {
        return NULL;
    }
    Elf64_Sym* symtab = (Elf64_Sym*) &file_content[symtab_header->sh_offset];

    int symbol_count = symtab_header->sh_size / sizeof(*symtab);
    for (int i = 0; i < symbol_count; i++) {
        char* symbol_name = &strtab[symtab[i].st_name];

        if (regexec(req_symbol_name, symbol_name, 0, NULL, 0) == 0) {
            return (void*) symtab[i].st_value;
        }
    }

    return NULL;
}

static void* base_addr = NULL;

int dl_iterate_phdr_get_base_addr(struct dl_phdr_info* info, size_t size, void* data) {
    if (strlen(info->dlpi_name) == 0) {
        base_addr = (void*) info->dlpi_addr;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    switch (argc) {
    case 0:
jump_location_0:
        call0();
        break;
    case 1:
jump_location_1:
        call1(argv[0]);
        break;
    case 2:
jump_location_2:
        call2(argv[0], argv[1]);
        break;
    case 3:
jump_location_3:
        call3(argv[0], argv[2]);
        break;
    case 4:
jump_location_4:
        call4(argv[0], argv[2]);
        break;
    case 5:
jump_location_5:
        call5(argv[0], argv[3], argv[4]);
        break;
    case 6:
jump_location_6:
        call6(argv[2], argv[6]);
        break;
    default:
        call_default();
        break;
    }

    if (argc == 1) {
        goto print_jumps;
    }

    /* below is only useful when debugging */
    
    dl_iterate_phdr(&dl_iterate_phdr_get_base_addr, NULL);

    char executable[200];
    int len = readlink("/proc/self/exe", executable, sizeof(executable));
    if (len < 0 || len == sizeof(executable)) {
        exit(1);
    }
    executable[len] = '\0';

    int fd = open(executable, O_RDONLY);
    if (fd < 0) {
        perror("open");
        fprintf(stderr, "failed to open file %s\n", executable);
        exit(1);
    }

    off_t file_len = lseek(fd, 0, SEEK_END);
    if (file_len < 0) {
        perror("lseek");
        exit(1);
    }

    void* file_content = mmap(NULL, file_len, PROT_READ, MAP_SHARED, fd, 0);
    if (file_content == NULL) {
        perror("mmap");
        exit(1);
    }

    if (close(fd) < 0) {
        perror("close");
        exit(1);
    }

    regex_t symbol_regex;
    if (regcomp(&symbol_regex, ".JUMP_TABLE_START.*", 0) != 0) {
        exit(1);
    }

    void* symbol_addr = elf64_get_first_symbol_addr(file_content, &symbol_regex);
    if (symbol_addr == NULL) {
        exit(1);
    }

    regfree(&symbol_regex);

    void* jump_table = (void*) (long int) (base_addr) + (long int) (symbol_addr);

    for (int i = 0; i < 7; i++) {
        void* jump_addr = (void*) (long int) jump_table + 4 * i;
        printf("%ld = %d\n", (long int) jump_addr, *((int32_t*) jump_addr));
    }

    printf("base address   : %ld\n", (long int) base_addr);
    printf("main() address : %ld\n", (long int) main);
    printf("jump table     : %ld\n", (long int) jump_table);

print_jumps:
    printf("jump location 0: %ld\n", (long int) &&jump_location_0);
    printf("jump location 1: %ld\n", (long int) &&jump_location_1);
    printf("jump location 2: %ld\n", (long int) &&jump_location_2);
    printf("jump location 3: %ld\n", (long int) &&jump_location_3);
    printf("jump location 4: %ld\n", (long int) &&jump_location_4);
    printf("jump location 5: %ld\n", (long int) &&jump_location_5);
    printf("jump location 6: %ld\n", (long int) &&jump_location_6);

    return 0;
}
