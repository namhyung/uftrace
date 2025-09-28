import uuid

from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import TrackEvent
from perfetto.trace_builder.proto_builder import TraceProtoBuilder

TRUSTED_ID = 8009

builder = None
filename = 'uftrace.data'
task_map = dict()

def create_new_track(tid, timestamp):
    global builder
    track_info = dict()
    track_info['track_id'] = uuid.uuid4().int & ((1 << 63) - 1)

    pkt = builder.add_packet()
    pkt.timestamp = timestamp

    desc = pkt.track_descriptor
    desc.uuid = track_info['track_id']
    # FIXME: handle process and thread differently, but we don't know pid
    desc.process.pid = tid
    desc.process.process_name = "task"

    track_info['desc'] = desc
    return track_info

def uftrace_begin(ctx):
    global builder
    builder = TraceProtoBuilder()

def uftrace_entry(ctx):
    global builder, task_map
    tid = int(ctx["tid"])
    ts = int(ctx["timestamp"])
    if tid not in task_map:
        # create a track just before the entry
        task_map[tid] = create_new_track(tid, ts - 1)
    info = task_map[tid]

    pkt = builder.add_packet()
    pkt.timestamp = ts
    pkt.trusted_packet_sequence_id = TRUSTED_ID
    pkt.track_event.type = TrackEvent.TYPE_SLICE_BEGIN
    pkt.track_event.track_uuid = info['track_id']
    pkt.track_event.name = ctx["name"]

def uftrace_exit(ctx):
    global builder, task_map
    tid = int(ctx["tid"])
    if tid not in task_map:
        # ignore exit when there's no matching entry
        return
    info = task_map[tid]
    ts = int(ctx["timestamp"])

    pkt = builder.add_packet()
    pkt.timestamp = ts
    pkt.trusted_packet_sequence_id = TRUSTED_ID
    pkt.track_event.type = TrackEvent.TYPE_SLICE_END
    pkt.track_event.track_uuid = info['track_id']

def uftrace_event(ctx):
    pass

def uftrace_end():
    global builder, filename
    output_filename = filename + ".perfetto-trace"
    with open(output_filename, 'wb') as f:
        f.write(builder.serialize())

    print(f"Trace written to {output_filename}")
    print("Open with https://ui.perfetto.dev.")
