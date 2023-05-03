#!/usr/bin/env python3
import os

def a():
    b()

def b():
    c()

def c():
    return os.getpid()

a()
