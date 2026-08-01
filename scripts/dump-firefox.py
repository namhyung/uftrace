# dump-firefox.py - Convert uftrace.data to Firefox's Gecko profile format
# SPDX-License-Identifier: GPL-2.0
#
# Adapted from the Linux kernel perf script tools/perf/scripts/python/gecko.py
# by Anup Sharma <anupnewsmail@gmail.com>.  perf hands a ready-made stack to
# Thread._add_sample per sample; uftrace is a tracer, so the front-end here
# keeps a call stack from uftrace_entry/uftrace_exit and emits samples at a
# fixed interval.  The Thread builder below is kept as-is.
#
#     $ uftrace record <program>
#     $ uftrace script -S scripts/dump-firefox.py

import json
from dataclasses import dataclass, field
from functools import reduce
from typing import Dict, List, NamedTuple, Optional, Tuple

StringID = int
StackID = int
FrameID = int
CategoryID = int
Milliseconds = float


# https://github.com/firefox-devtools/profiler/blob/53970305b51b9b472e26d7457fee1d66cd4e2737/src/types/profile.js#L425
# Follow Brendan Gregg's Flamegraph convention: orange for kernel and yellow for user space by default.
CATEGORIES = [
    {"name": 'User', "color": 'yellow', "subcategories": ['Other']},
    {"name": 'Kernel', "color": 'orange', "subcategories": ['Other']},
]

# The product name is used by the profiler UI to show the Operating system and Processor.
PRODUCT = 'uftrace'




# The category index is used by the profiler UI to show the color of the flame graph.
USER_CATEGORY_INDEX = 0
KERNEL_CATEGORY_INDEX = 1

# https://github.com/firefox-devtools/profiler/blob/53970305b51b9b472e26d7457fee1d66cd4e2737/src/types/gecko-profile.js#L156
class Frame(NamedTuple):
	string_id: StringID
	relevantForJS: bool
	innerWindowID: int
	implementation: None
	optimizations: None
	line: None
	column: None
	category: CategoryID
	subcategory: int

# https://github.com/firefox-devtools/profiler/blob/53970305b51b9b472e26d7457fee1d66cd4e2737/src/types/gecko-profile.js#L216
class Stack(NamedTuple):
	prefix_id: Optional[StackID]
	frame_id: FrameID

# https://github.com/firefox-devtools/profiler/blob/53970305b51b9b472e26d7457fee1d66cd4e2737/src/types/gecko-profile.js#L90
class Sample(NamedTuple):
	stack_id: Optional[StackID]
	time_ms: Milliseconds
	responsiveness: int

@dataclass
class Thread:
	"""A builder for a profile of the thread.

	Attributes:
		comm: Thread command-line (name).
		pid: process ID of containing process.
		tid: thread ID.
		samples: Timeline of profile samples.
		frameTable: interned stack frame ID -> stack frame.
		stringTable: interned string ID -> string.
		stringMap: interned string -> string ID.
		stackTable: interned stack ID -> stack.
		stackMap: (stack prefix ID, leaf stack frame ID) -> interned Stack ID.
		frameMap: Stack Frame string -> interned Frame ID.
		comm: str
		pid: int
		tid: int
		samples: List[Sample] = field(default_factory=list)
		frameTable: List[Frame] = field(default_factory=list)
		stringTable: List[str] = field(default_factory=list)
		stringMap: Dict[str, int] = field(default_factory=dict)
		stackTable: List[Stack] = field(default_factory=list)
		stackMap: Dict[Tuple[Optional[int], int], int] = field(default_factory=dict)
		frameMap: Dict[str, int] = field(default_factory=dict)
	"""
	comm: str
	pid: int
	tid: int
	samples: List[Sample] = field(default_factory=list)
	frameTable: List[Frame] = field(default_factory=list)
	stringTable: List[str] = field(default_factory=list)
	stringMap: Dict[str, int] = field(default_factory=dict)
	stackTable: List[Stack] = field(default_factory=list)
	stackMap: Dict[Tuple[Optional[int], int], int] = field(default_factory=dict)
	frameMap: Dict[str, int] = field(default_factory=dict)

	def _intern_stack(self, frame_id: int, prefix_id: Optional[int]) -> int:
		"""Gets a matching stack, or saves the new stack. Returns a Stack ID."""
		key = f"{frame_id}" if prefix_id is None else f"{frame_id},{prefix_id}"
		# key = (prefix_id, frame_id)
		stack_id = self.stackMap.get(key)
		if stack_id is None:
			# return stack_id
			stack_id = len(self.stackTable)
			self.stackTable.append(Stack(prefix_id=prefix_id, frame_id=frame_id))
			self.stackMap[key] = stack_id
		return stack_id

	def _intern_string(self, string: str) -> int:
		"""Gets a matching string, or saves the new string. Returns a String ID."""
		string_id = self.stringMap.get(string)
		if string_id is not None:
			return string_id
		string_id = len(self.stringTable)
		self.stringTable.append(string)
		self.stringMap[string] = string_id
		return string_id

	def _intern_frame(self, frame_str: str, is_kernel: bool) -> int:
		"""Gets a matching stack frame, or saves the new frame. Returns a Frame ID."""
		frame_id = self.frameMap.get(frame_str)
		if frame_id is not None:
			return frame_id
		frame_id = len(self.frameTable)
		self.frameMap[frame_str] = frame_id
		string_id = self._intern_string(frame_str)

		symbol_name_to_category = KERNEL_CATEGORY_INDEX if is_kernel else USER_CATEGORY_INDEX

		self.frameTable.append(Frame(
			string_id=string_id,
			relevantForJS=False,
			innerWindowID=0,
			implementation=None,
			optimizations=None,
			line=None,
			column=None,
			category=symbol_name_to_category,
			subcategory=None,
		))
		return frame_id

	def _add_sample(self, comm: str, stack: List[Tuple[str, bool]], time_ms: Milliseconds) -> None:
		"""Add a timestamped stack trace sample to the thread builder.
		Args:
			comm: command-line (name) of the thread at this sample
			stack: sampled stack frames. Root first, leaf last.
			time_ms: timestamp of sample in milliseconds.
		"""
		# Ihreads may not set their names right after they are created.
		# Instead, they might do it later. In such situations, to use the latest name they have set.
		if self.comm != comm:
			self.comm = comm

		prefix_stack_id = reduce(lambda prefix_id, frame: self._intern_stack
						(self._intern_frame(frame[0], frame[1]), prefix_id), stack, None)
		if prefix_stack_id is not None:
			self.samples.append(Sample(stack_id=prefix_stack_id,
									time_ms=time_ms,
									responsiveness=0))

	def _to_json_dict(self) -> Dict:
		"""Converts current Thread to GeckoThread JSON format."""
		# Gecko profile format is row-oriented data as List[List],
		# And a schema for interpreting each index.
		# Schema:
		# https://github.com/firefox-devtools/profiler/blob/main/docs-developer/gecko-profile-format.md
		# https://github.com/firefox-devtools/profiler/blob/53970305b51b9b472e26d7457fee1d66cd4e2737/src/types/gecko-profile.js#L230
		return {
			"tid": self.tid,
			"pid": self.pid,
			"name": self.comm,
			# https://github.com/firefox-devtools/profiler/blob/53970305b51b9b472e26d7457fee1d66cd4e2737/src/types/gecko-profile.js#L51
			"markers": {
				"schema": {
					"name": 0,
					"startTime": 1,
					"endTime": 2,
					"phase": 3,
					"category": 4,
					"data": 5,
				},
				"data": [],
			},

			# https://github.com/firefox-devtools/profiler/blob/53970305b51b9b472e26d7457fee1d66cd4e2737/src/types/gecko-profile.js#L90
			"samples": {
				"schema": {
					"stack": 0,
					"time": 1,
					"responsiveness": 2,
				},
				"data": self.samples
			},

			# https://github.com/firefox-devtools/profiler/blob/53970305b51b9b472e26d7457fee1d66cd4e2737/src/types/gecko-profile.js#L156
			"frameTable": {
				"schema": {
					"location": 0,
					"relevantForJS": 1,
					"innerWindowID": 2,
					"implementation": 3,
					"optimizations": 4,
					"line": 5,
					"column": 6,
					"category": 7,
					"subcategory": 8,
				},
				"data": self.frameTable,
			},

			# https://github.com/firefox-devtools/profiler/blob/53970305b51b9b472e26d7457fee1d66cd4e2737/src/types/gecko-profile.js#L216
			"stackTable": {
				"schema": {
					"prefix": 0,
					"frame": 1,
				},
				"data": self.stackTable,
			},
			"stringTable": self.stringTable,
			"registerTime": 0,
			"unregisterTime": None,
			"processType": "default",
		}

events = {}   # tid -> [(timestamp_ns, kind, name)]; kind 1=enter 0=exit
first_pid = {'pid': None}
TARGET_SAMPLES = 10000


def uftrace_begin(ctx):
    pass


def uftrace_entry(ctx):
    tid = int(ctx["tid"])
    if first_pid['pid'] is None:
        first_pid['pid'] = tid
    events.setdefault(tid, []).append((int(ctx["timestamp"]), 1, ctx["name"], ctx["kernel"]))


def uftrace_exit(ctx):
    tid = int(ctx["tid"])
    events.setdefault(tid, []).append((int(ctx["timestamp"]), 0, None, False))


def uftrace_event(ctx):
    pass


def uftrace_end():
    all_ts = [ts for evs in events.values() for ts, _, _, _ in evs]
    if not all_ts:
        print("uftrace: no function events found, nothing to convert")
        return
    start_ns = min(all_ts)
    interval_ns = max(1, (max(all_ts) - start_ns) // TARGET_SAMPLES)
    pid = first_pid['pid']

    threads = []
    for tid, evs in events.items():
        comm = "main" if tid == pid else "tid %d" % tid
        thread = Thread(comm=comm, pid=pid, tid=tid)
        stack = []
        next_ns = evs[0][0]
        for ts, kind, name, kernel in evs:
            while next_ns < ts:
                thread._add_sample(comm, stack, (next_ns - start_ns) / 1e6)
                next_ns += interval_ns
            if kind == 1:
                stack.append((name, kernel))
            elif stack:
                stack.pop()
        threads.append(thread._to_json_dict())

    gecko_profile = {
        "meta": {
            "interval": interval_ns / 1e6,
            "processType": 0,
            "product": PRODUCT,
            "stackwalk": 1,
            "debug": 0,
            "gcpoison": 0,
            "asyncstack": 1,
            "startTime": 0,
            "shutdownTime": None,
            "version": 24,
            "presymbolicated": True,
            "categories": CATEGORIES,
            "markerSchema": [],
        },
        "libs": [],
        "threads": threads,
        "processes": [],
        "pausedRanges": [],
    }

    output = 'uftrace.data.firefox-trace'
    with open(output, 'w') as f:
        json.dump(gecko_profile, f)
    print("Trace written to " + output)
    print("Open with https://profiler.firefox.com.")
