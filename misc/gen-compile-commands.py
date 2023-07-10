#!/usr/bin/env python

import os
import subprocess as sp
import sys

def do_dry_make():
    make_cmds = 'make V=1 --dry-run'
    with sp.Popen(make_cmds.split(), stdout=sp.PIPE) as p:
        lines = p.communicate()[0].decode(errors='ignore').split('\n')
        return lines

def main():
    if not os.path.exists('Makefile'):
        print('error: Makefile not found.')
        return -1

    with open('compile_commands.json', 'w') as f:
        f.write('[')
        needs_comma = False
        directory = os.getcwd()
        lines = do_dry_make()
        for line in lines:
            command = line
            if command[:3] != 'gcc' and command[:5] != 'clang':
                # We're only interested in compilation commands
                # so skip otherwise.
                continue
            file = ''
            words = command.split()
            for word in words:
                if word[-2:] == '.c':
                    file = word
            if file == '':
                continue
            if 'libtraceevent' in file:
                continue
            command = command.replace('"', '\\"')

            if needs_comma:
                f.write(',')
            f.write('\n{\n')
            f.write('  "directory": "%s",\n' % directory)
            f.write('  "command": "%s",\n' % command)
            f.write('  "file": "%s"\n' % file)
            f.write('}')
            needs_comma = True

        f.write('\n]\n')

if __name__ == '__main__':
    sys.exit(main())
