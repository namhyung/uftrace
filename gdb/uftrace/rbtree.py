#
# gdb helper commands and functions for uftrace debugging
#
#  rbtree tools
#
# Copyright (c) LG Electronics, 2018
#
# Authors:
#  Namhyung Kim <namhyung.kim@lge.com>
#
# This work is licensed under the terms of the GNU GPL version 2.
#

import gdb
from uftrace import utils

rb_root = utils.CachedType("struct rb_root")
rb_node = utils.CachedType("struct rb_node")

def rb_color(node):
    """Return the color of a node.
    red -> 0 | black -> 1"""
    if node.address == 0:
        return 1

    if node['rb_parent_color'] % 2 == 0:
        return 0
    else:
        return 1

def rb_check(node, val_min=-1, val_max=-1, gdbtype=None, val_field="start"):
    if node.address == 0:
        return 1

    # check order
    if gdbtype is not None:
        node_container = utils.container_of(node.address, gdbtype.pointer(), "node").dereference()
        val = int(node_container[val_field])
        if val < val_min:
            gdb.write(f"node {node.address} is not ordered (val={val} < min={val_min})\n")
            return -1
        if val > val_max and val_max != -1: # use -1 as infinity value for val_max
            gdb.write(f"node {node.address} is not ordered (val={val} > max={val_max})\n")
            return -1
    else:
        val = -1

    left = node['rb_left'].dereference()
    right = node['rb_right'].dereference()

    # check that a red node has black children
    if rb_color(node) == 0:
        if rb_color(left) == 0:
            gdb.write(f"red node {node.address} has red left child {left}\n")
            return -1
        if rb_color(right) == 0:
            gdb.write(f"red node {node.address} has red right child {right}\n")
            return -1

    # recursively check that paths to NULL leafs have as many black nodes
    left_black_count = rb_check(left, val_min, val, gdbtype)
    if left_black_count == -1:
        return -1

    right_black_count = rb_check(right, val, val_max, gdbtype)
    if right_black_count == -1:
        return -1

    if left_black_count != right_black_count:
        gdb.write(f"node @ {node.address}: {left_black_count} on left != {right_black_count} on right\n")
        return -1
    else:
        black_count = left_black_count
        if rb_color(node) == 1:
            black_count += 1
        return black_count


class UftRbtreeCheck(gdb.Command):
    """Check if a rbtree has a valid structure.

    A red-black tree is a binary search tree with the following constraints:
        1. Every node is either red or black
        2. All NULL leafs are defined as black
        3. A red node does not have a red child
        4. Every path from a given node to any of its descendant NULL leafs goes
        through the same number of black nodes
    Source: https://wikipedia.org/wiki/Red%E2%80%93black_tree

                           _ROOT_
                          /      \             Legend:
                     NODE          NODE         UPPERCASE: BLACK
                    /    \        /    \        lowercase: red
                node    NULL  node    NULL
               /    \        /    \
             NULL  NULL    NULL  NULL
    """

    def __init__(self):
        super(UftRbtreeCheck, self).__init__("uft-rbtree-check", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = arg.split()
        if len(argv) == 0:
            gdb.write("Usage: uft-rbtree-check RBTREE [CONTAINER_TYPE]\n")
            return
        tr = utils.gdb_eval_or_none(argv[0])
        if tr is None:
            gdb.write(f"{argv[0]} tree not found\n")
            return
        if len(argv) > 1:
            container_type = utils.CachedType(" ".join(argv[1:]))
            gdbtype = container_type.get_type()
        else:
            gdbtype = None
            gdb.write("[info] no container type given: skipping order check\n")

        node = tr['rb_node'].dereference()
        if rb_check(node, gdbtype=gdbtype) == -1:
            gdb.write(f"{arg} @ {node.address} is NOT a valid rbtree\n")
        else:
            gdb.write(f"{arg} @ {node.address} is a valid rbtree\n")

UftRbtreeCheck()

def rb_print(node, depth=0, gdbtype=None):
    if depth > 0:
        gdb.write(" |")
        gdb.write(f"{'  |'*(depth-1)}")
        gdb.write("_")

    if node.address == 0:
        gdb.write("(b) NULL\n")
        return

    gdb.write(f"({'r' if rb_color(node) == 0 else 'b'}) {node.address} ")
    if gdbtype is not None:
        node_container = utils.container_of(node.address, gdbtype.pointer(), "node").dereference()
        gdb.write(f"{node_container}")
    else:
        gdb.write(f"{node}")
    gdb.write("\n")

    rb_print(node['rb_left'].dereference(), depth+1, gdbtype)
    rb_print(node['rb_right'].dereference(), depth+1, gdbtype)


class UftRbtreePrint(gdb.Command):
    """Display a textual representation of an rbtree."""

    def __init__(self):
        super(UftRbtreePrint, self).__init__("uft-rbtree-print", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = arg.split()
        if len(argv) == 0:
            gdb.write("Usage: uft-rbtree-print RBTREE [CONTAINER_TYPE]\n")
            return
        tr = utils.gdb_eval_or_none(argv[0])
        if tr is None:
            gdb.write(f"{argv[0]} tree not found\n")
            return
        if len(argv) >= 2:
            container_type = utils.CachedType(" ".join(argv[1:]))
            gdbtype = container_type.get_type()
        else:
            gdbtype = None

        node = tr['rb_node'].dereference()
        gdb.write(f"{argv[0]}\n")
        rb_print(node, gdbtype=gdbtype)

UftRbtreePrint()

def rb_first(root):
    if root.type == rb_root.get_type().pointer():
        root = root.dereference()
    elif root.type != rb_root.get_type():
        raise gdb.GdbError("Must be struct rb_root not {}"
                           .format(root.type))

    node = root['rb_node'].dereference()
    if node.address == 0:
        return None

    if node.type != rb_node.get_type():
        raise gdb.GdbError("Must be struct rb_ndoe not {}"
                           .format(node.type))

    left = node['rb_left'].dereference()
    while left.address != 0:
        node = left
        left = node['rb_left'].dereference()

    return node


def rb_last(root):
    if root.type == rb_root.get_type().pointer():
        root = root.dereference()
    elif root.type != rb_root.get_type():
        raise gdb.GdbError("Must be struct rb_root not {}"
                           .format(root.type))

    node = root['rb_node'].dereference()
    if node.address == 0:
        return None

    right = node['rb_right'].dereference()
    while right.address != 0:
        node = right
        right = node['rb_right'].dereference()

    return node


def rb_parent(node):
    addr = int(node['rb_parent_color'])
    addr &= ~3  # clear color bit
    if addr == 0:
        return None

    # Value.address is read-only, just create a new value
    # using Value.cast() after changing its address
    node = gdb.Value(addr)
    p = node.cast(rb_node.get_type().pointer())
    return p.dereference()


def rb_next(node):
    if node.type == rb_node.get_type().pointer():
        node = node.dereference()
    elif node.type != rb_node.get_type():
        raise gdb.GdbError("Must be struct rb_node not {}"
                           .format(node.type))

    parent = rb_parent(node)
    if parent is not None and parent.address == node.address:
        return None

    r = node['rb_right'].dereference()
    if r.address != 0:
        node = r
        left = node['rb_left'].dereference()
        while left.address != 0:
            node = left
            left = node['rb_left'].dereference()
        return node

    while parent is not None:
        right_child = parent['rb_right'].dereference()
        if node.address != right_child.address:
            break
        node = parent
        parent = rb_parent(node)

    return parent


def rb_prev(node):
    if node.type == rb_node.get_type().pointer():
        node = node.dereference()
    elif node.type != rb_node.get_type():
        raise gdb.GdbError("Must be struct rb_node not {}"
                           .format(node.type))

    parent = rb_parent(node)
    if parent is not None and parent.address == node.address:
        return None

    l = node['rb_left'].dereference()
    if l.address != 0:
        node = l
        right = node['rb_right'].dereference()
        while right.address != 0:
            node = right
            right = node['rb_right'].dereference()
        return node

    while parent is not None:
        left_child = parent['rb_left'].dereference()
        if node.address != left_child.address:
            break
        node = parent
        parent = rb_parent(node)

    return parent


def rb_for_each(root):
    node = rb_first(root)
    while node is not None:
        yield node.address
        node = rb_next(node)


def rb_for_each_entry(head, gdbtype, member):
    for node in rb_for_each(head):
        if node.type != rb_node.get_type().pointer():
            raise TypeError("Type {} found. Expected struct rb_node *."
                            .format(node.type))
        yield utils.container_of(node, gdbtype, member)
