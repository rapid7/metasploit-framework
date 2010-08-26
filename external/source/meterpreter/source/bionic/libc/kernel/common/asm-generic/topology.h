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
#ifndef _ASM_GENERIC_TOPOLOGY_H
#define _ASM_GENERIC_TOPOLOGY_H

#ifndef cpu_to_node
#define cpu_to_node(cpu) (0)
#endif
#ifndef parent_node
#define parent_node(node) (0)
#endif
#ifndef node_to_cpumask
#define node_to_cpumask(node) (cpu_online_map)
#endif
#ifndef node_to_first_cpu
#define node_to_first_cpu(node) (0)
#endif
#ifndef pcibus_to_node
#define pcibus_to_node(node) (-1)
#endif

#ifndef pcibus_to_cpumask
#define pcibus_to_cpumask(bus) (pcibus_to_node(bus) == -1 ?   CPU_MASK_ALL :   node_to_cpumask(pcibus_to_node(bus))   )
#endif

#endif
