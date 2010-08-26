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
#ifndef _ASM_GENAPIC_H
#define _ASM_GENAPIC_H 1

#include <asm/mpspec.h>

struct mpc_config_translation;
struct mpc_config_bus;
struct mp_config_table;
struct mpc_config_processor;

struct genapic {
 char *name;
 int (*probe)(void);

 int (*apic_id_registered)(void);
 cpumask_t (*target_cpus)(void);
 int int_delivery_mode;
 int int_dest_mode;
 int ESR_DISABLE;
 int apic_destination_logical;
 unsigned long (*check_apicid_used)(physid_mask_t bitmap, int apicid);
 unsigned long (*check_apicid_present)(int apicid);
 int no_balance_irq;
 int no_ioapic_check;
 void (*init_apic_ldr)(void);
 physid_mask_t (*ioapic_phys_id_map)(physid_mask_t map);

 void (*setup_apic_routing)(void);
 int (*multi_timer_check)(int apic, int irq);
 int (*apicid_to_node)(int logical_apicid);
 int (*cpu_to_logical_apicid)(int cpu);
 int (*cpu_present_to_apicid)(int mps_cpu);
 physid_mask_t (*apicid_to_cpu_present)(int phys_apicid);
 int (*mpc_apic_id)(struct mpc_config_processor *m,
 struct mpc_config_translation *t);
 void (*setup_portio_remap)(void);
 int (*check_phys_apicid_present)(int boot_cpu_physical_apicid);
 void (*enable_apic_mode)(void);
 u32 (*phys_pkg_id)(u32 cpuid_apic, int index_msb);

 void (*mpc_oem_bus_info)(struct mpc_config_bus *, char *,
 struct mpc_config_translation *);
 void (*mpc_oem_pci_bus)(struct mpc_config_bus *,
 struct mpc_config_translation *);

 int (*mps_oem_check)(struct mp_config_table *mpc, char *oem,
 char *productid);
 int (*acpi_madt_oem_check)(char *oem_id, char *oem_table_id);

 unsigned (*get_apic_id)(unsigned long x);
 unsigned long apic_id_mask;
 unsigned int (*cpu_mask_to_apicid)(cpumask_t cpumask);

};

#define APICFUNC(x) .x = x,

#define IPIFUNC(x)

#define APIC_INIT(aname, aprobe) {   .name = aname,   .probe = aprobe,   .int_delivery_mode = INT_DELIVERY_MODE,   .int_dest_mode = INT_DEST_MODE,   .no_balance_irq = NO_BALANCE_IRQ,   .ESR_DISABLE = esr_disable,   .apic_destination_logical = APIC_DEST_LOGICAL,   APICFUNC(apic_id_registered)   APICFUNC(target_cpus)   APICFUNC(check_apicid_used)   APICFUNC(check_apicid_present)   APICFUNC(init_apic_ldr)   APICFUNC(ioapic_phys_id_map)   APICFUNC(setup_apic_routing)   APICFUNC(multi_timer_check)   APICFUNC(apicid_to_node)   APICFUNC(cpu_to_logical_apicid)   APICFUNC(cpu_present_to_apicid)   APICFUNC(apicid_to_cpu_present)   APICFUNC(mpc_apic_id)   APICFUNC(setup_portio_remap)   APICFUNC(check_phys_apicid_present)   APICFUNC(mpc_oem_bus_info)   APICFUNC(mpc_oem_pci_bus)   APICFUNC(mps_oem_check)   APICFUNC(get_apic_id)   .apic_id_mask = APIC_ID_MASK,   APICFUNC(cpu_mask_to_apicid)   APICFUNC(acpi_madt_oem_check)   IPIFUNC(send_IPI_mask)   IPIFUNC(send_IPI_allbutself)   IPIFUNC(send_IPI_all)   APICFUNC(enable_apic_mode)   APICFUNC(phys_pkg_id)   }

#endif
