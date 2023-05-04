#!/usr/bin/env python3
import time

def foo():
    bar()
    time.sleep(0.1)
    baz()

def bar():
    pass

def baz():
    pass

if __name__ == '__main__':
    foo()
