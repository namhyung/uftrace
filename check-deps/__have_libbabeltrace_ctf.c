#include <babeltrace/ctf-writer/writer.h>
#include <babeltrace/ctf-writer/clock.h>
#include <babeltrace/ctf-writer/stream.h>
#include <babeltrace/ctf-writer/event.h>
#include <babeltrace/ctf-writer/event-types.h>
#include <babeltrace/ctf-writer/event-fields.h>
#include <babeltrace/ctf/events.h>

int main(void)
{
    char trace_path[] = "/tmp/uftrace.ctf";
    struct bt_ctf_writer *writer = bt_ctf_writer_create(trace_path);
    struct bt_ctf_clock *clock = bt_ctf_clock_create("monotonic");

    free(writer);
    free(clock);

	return 0;
}
