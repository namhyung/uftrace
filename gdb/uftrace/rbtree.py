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
