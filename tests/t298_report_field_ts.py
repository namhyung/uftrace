#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'ts-report', """
  Total min ts        Total max ts         Self min ts         Self max ts  Function
==================  ==================  ==================  ==================  ====================
     477.331731658       477.331731658       477.331731658       477.331731658  main
     477.334554430       477.331731718       477.331731718       477.334554430  foo
     477.335653399       477.331731858       477.335653399       477.331731858  child
""".strip())

    def prepare(self):
        self.subcmd = 'record'
        self.option = '-F main'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '-f total-min-ts,total-max-ts,self-min-ts,self-max-ts'

    def sort(self, output):
        result = []

        for ln in output.split('\n'):
            if not ln.strip():
                continue
            line = ln.split()
            if not line:
                continue

            if line[0] in ('Total', 'Self') or line[0].startswith('='):
                continue

            func = line[-1]

            try:
                total_min_ts = float(line[0])
                total_max_ts = float(line[1])
                self_min_ts  = float(line[2])
                self_max_ts  = float(line[3])

                if total_min_ts <= 0 or total_max_ts <= 0 or \
                        self_min_ts <= 0 or self_max_ts <= 0:
                    result.append('%s : NG' % func)
                    continue

                if func == 'main':
                    # main() is called only once.
                    # Thus, the min timestamp and max timestamp must be identical.
                    if total_min_ts == total_max_ts and self_min_ts == self_max_ts:
                        result.append('%s : OK' % func)
                    else:
                        result.append('%s : NG' % func)

                elif func == 'foo':
                    # foo() is called twice with different distributions:
                    # Call 1 (Earlier): Large Total Time, Small Self Time
                    # Call 2 (Later)  : Small Total Time, Large Self Time
                    # Therefore, total_min_ts (Call 2) must equal self_max_ts (Call 2),
                    # and total_max_ts (Call 1) must equal self_min_ts (Call 1).
                    if total_min_ts == self_max_ts and total_max_ts == self_min_ts and total_min_ts != total_max_ts:
                        result.append('%s : OK' % func)
                    else:
                        result.append('%s : NG' % func)

                elif func == 'child':
                    # child() has no child functions, meaning Total Time equals Self Time.
                    # Thus, total_min_ts must equal self_min_ts, and total_max_ts must equal self_max_ts.
                    if total_min_ts == self_min_ts and total_max_ts == self_max_ts and total_min_ts != total_max_ts:
                        result.append('%s : OK' % func)
                    else:
                        result.append('%s : NG' % func)

            except ValueError:
                return output

        return '\n'.join(result)
