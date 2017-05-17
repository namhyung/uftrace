#include <babeltrace/ctf-writer/writer.h>
#include <babeltrace/ctf-writer/clock.h>
#include <babeltrace/ctf-writer/stream.h>
#include <babeltrace/ctf-writer/event.h>
#include <babeltrace/ctf-writer/event-types.h>
#include <babeltrace/ctf-writer/event-fields.h>
#include <babeltrace/ctf/events.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>
#include <libgen.h>

#define CPU_FIELD_NAME "cpu_id"
#define VTID_FIELD_NAME "vtid"
#define VPID_FIELD_NAME "vpid"
#define ADDR_FIELD_NAME "addr"
#define NAME_FIELD_NAME "name"
#define PROCNAME_FIELD_NAME "procname"
#define FUNC_ENTRY_EVENT_NAME "func_entry"
#define FUNC_EXIT_EVENT_NAME "func_exit"
#define MAPPING_BUF_SIZE 1000

FILE *fmapping;
char* procname;
static char trace_path[] = "./uftrace.ctf";
static struct bt_ctf_writer *writer = NULL;
static struct bt_ctf_stream *stream;
static struct bt_ctf_clock *clock;
static struct bt_ctf_event_class *func_entry_event_class;
static struct bt_ctf_event_class *func_exit_event_class;

static uint64_t mapping_symbols[MAPPING_BUF_SIZE];
static int mapping_counter = 0;

static bool can_be_mapped(uint64_t addr)
{
    for(int i = 0; i < mapping_counter; i++)
        if(addr == mapping_symbols[i])
            return false;
    return true && mapping_counter < MAPPING_BUF_SIZE;
}


static void combine(char *destination, const char *path1, const char *path2) {
  char sep = '/';
  if (path1 && *path1) {
    int len = strlen(path1);
    strcpy(destination, path1);

    if (destination[len - 1] == sep) {
      if (path2 && *path2) {
        strcpy(destination + len, (*path2 == sep) ? (path2 + 1) : path2);
      }
    }
    else {
      if (path2 && *path2) {
        if (*path2 == sep)
          strcpy(destination + len, path2);
        else {
          destination[len] = sep;
          strcpy(destination + len + 1, path2);
        }
      }
    }
  }
  else if (path2 && *path2)
    strcpy(destination, path2);
  else
    destination[0] = '\0';
}

static FILE* init_mapping_file()
{
    // init mapping path
    char mapping_path[sizeof(trace_path) + 8];
    char mapping_file[sizeof(mapping_path) + 15];
    combine(mapping_path, trace_path, "mapping");
    combine(mapping_file, mapping_path, "mapping.sym");
    // create mapping folder when it not exist
    struct stat st = {0};
    if (stat(mapping_path, &st) == -1)
        mkdir(mapping_path, 0700);

    return fopen(mapping_file, "w");
}

void ctf_init(char* host, char* exename)
{
    procname = basename(exename);
    struct bt_ctf_stream_class *stream_class;
    writer = bt_ctf_writer_create(trace_path);

    bt_ctf_writer_add_environment_field(writer, "hostname", host);
    bt_ctf_writer_add_environment_field(writer, "domain", "ust");
    bt_ctf_writer_add_environment_field(writer, "tracer_name", "uftrace");
    clock = bt_ctf_clock_create("monotonic");
    bt_ctf_writer_add_clock(writer, clock);

    /* Define a stream class */
    stream_class = bt_ctf_stream_class_create("channel");
    bt_ctf_stream_class_set_clock(stream_class, clock);

    // Create field types
    struct bt_ctf_field_type *int_8_type = bt_ctf_field_type_integer_create(32);
    struct bt_ctf_field_type *int_32_type = bt_ctf_field_type_integer_create(32);
    struct bt_ctf_field_type *uint_64_type = bt_ctf_field_type_integer_create(64);
    struct bt_ctf_field_type *string_type = bt_ctf_field_type_string_create();

    bt_ctf_field_type_integer_set_signed(int_32_type, 1);
    bt_ctf_field_type_integer_set_signed(int_8_type, 1);
    bt_ctf_field_type_string_set_encoding(string_type, CTF_STRING_NONE);

    /* create event class */
    func_entry_event_class = bt_ctf_event_class_create(FUNC_ENTRY_EVENT_NAME);
    func_exit_event_class = bt_ctf_event_class_create(FUNC_EXIT_EVENT_NAME);

    /* event for entry */
    bt_ctf_event_class_add_field(func_entry_event_class, uint_64_type, ADDR_FIELD_NAME);
    bt_ctf_event_class_add_field(func_entry_event_class, string_type, NAME_FIELD_NAME);
    bt_ctf_event_class_add_field(func_entry_event_class, string_type, PROCNAME_FIELD_NAME);
    bt_ctf_event_class_add_field(func_entry_event_class, int_32_type, VTID_FIELD_NAME);
    bt_ctf_event_class_add_field(func_entry_event_class, int_32_type, VPID_FIELD_NAME);
    /* event for exit */
    bt_ctf_event_class_add_field(func_exit_event_class, uint_64_type, ADDR_FIELD_NAME);
    bt_ctf_event_class_add_field(func_exit_event_class, string_type, NAME_FIELD_NAME);
    bt_ctf_event_class_add_field(func_exit_event_class, string_type, PROCNAME_FIELD_NAME);
    bt_ctf_event_class_add_field(func_exit_event_class, int_32_type, VTID_FIELD_NAME);
    bt_ctf_event_class_add_field(func_exit_event_class, int_32_type, VPID_FIELD_NAME);


    bt_ctf_stream_class_add_event_class(stream_class, func_entry_event_class);
    bt_ctf_stream_class_add_event_class(stream_class, func_exit_event_class);

    /* Instantiate a stream */
    stream = bt_ctf_writer_create_stream(writer, stream_class);

    // init file mapping
    fmapping = init_mapping_file();
}

void ctf_append_event(int tid, int pid, uint64_t timestamp, uint64_t func_addr,
                      char* func_name, bool is_entry)
{
    struct bt_ctf_event *event = is_entry ? bt_ctf_event_create(func_entry_event_class)
        :  bt_ctf_event_create(func_exit_event_class);
    bt_ctf_clock_set_time(clock, timestamp);

    // set address field value
    struct bt_ctf_field *func_addr_field = bt_ctf_event_get_payload(event, ADDR_FIELD_NAME);
    bt_ctf_field_unsigned_integer_set_value(func_addr_field, func_addr);
    // set function name
    struct bt_ctf_field *func_name_field = bt_ctf_event_get_payload(event, NAME_FIELD_NAME);
    bt_ctf_field_string_set_value(func_name_field, func_name);
    // set vtid field value
    struct bt_ctf_field *vtid_field = bt_ctf_event_get_payload(event, VTID_FIELD_NAME);
    bt_ctf_field_signed_integer_set_value(vtid_field, tid);
    // set vpid field value
    struct bt_ctf_field *vpid_field = bt_ctf_event_get_payload(event, VPID_FIELD_NAME);
    bt_ctf_field_signed_integer_set_value(vpid_field, pid);
    // set procname field value
    struct bt_ctf_field *procname_field = bt_ctf_event_get_payload(event, PROCNAME_FIELD_NAME);
    bt_ctf_field_string_set_value(procname_field, procname);

    /* Append event to stream */
    bt_ctf_stream_append_event(stream, event);

    /*Append function name to mapping */
    if (fmapping != NULL && can_be_mapped(func_addr)){
        fprintf(fmapping, "%04"PRIx64" T %s\n", func_addr, func_name);
        mapping_symbols[mapping_counter++] = func_addr;
    }
}

void ctf_set_cpu(int cpu)
{

}

void ctf_flush()
{
    // flush stream
    bt_ctf_stream_flush(stream);
    bt_ctf_writer_flush_metadata(writer);

    free(writer);
    free(stream);
    free(clock);
    free(func_entry_event_class);
    free(func_exit_event_class);

    fclose(fmapping);

    printf("Traces were saved at %s\n", trace_path);
}

