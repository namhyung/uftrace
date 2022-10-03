#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
<html>
<body>
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>
  var config = {
  startOnLoad: true,
  maxTextSize: 99999999,
  flowchart: { useMaxWidth: false }
  };
  mermaid.initialize(config);
</script>
<h2>Function Call Graph for <span style="color:blue">t-abc</span></h2>
<div class="mermaid">
flowchart TB
  0_0["t-abc"] -->|1| 1_1["main"];
  1_1["main"] -->|1| 2_2["a"];
  2_2["a"] -->|1| 3_3["b"];
  3_3["b"] -->|1| 4_4["c"];
</div>
</body>
</html>
""", sort='mermaid')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'dump'
        self.option = '-F main -D 4 --mermaid'
