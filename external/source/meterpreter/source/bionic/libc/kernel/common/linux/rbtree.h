/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef _LINUX_RBTREE_H
#define _LINUX_RBTREE_H

#include <linux/kernel.h>
#include <linux/stddef.h>

struct rb_node
{
 unsigned long rb_parent_color;
#define RB_RED 0
#define RB_BLACK 1
 struct rb_node *rb_right;
 struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));

struct rb_root
{
 struct rb_node *rb_node;
};

#define rb_parent(r) ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_color(r) ((r)->rb_parent_color & 1)
#define rb_is_red(r) (!rb_color(r))
#define rb_is_black(r) rb_color(r)
#define rb_set_red(r) do { (r)->rb_parent_color &= ~1; } while (0)
#define rb_set_black(r) do { (r)->rb_parent_color |= 1; } while (0)

#define RB_ROOT (struct rb_root) { NULL, }
#define rb_entry(ptr, type, member) container_of(ptr, type, member)
#define RB_EMPTY_ROOT(root) ((root)->rb_node == NULL)
#define RB_EMPTY_NODE(node) (rb_parent(node) != node)
#define RB_CLEAR_NODE(node) (rb_set_parent(node, node))

#endif
