#ifndef __pwn__lsym__
#define __pwn__lsym__

#include <stdio.h>
#include "import.h"

#define JUNK_VALUE 0x1337133713371337


typedef struct kernel_fake_stack {
    uint64_t __cnt;
    uint64_t __padding[0x4999];
    uint64_t __rop_chain[0x5000];
} kernel_fake_stack_t;

#define LSYM_PAYLOAD_VTABLE 1

struct segment_command_64 *find_segment_64(struct mach_header_64 *mh, const char *segname);
struct section_64 *find_section_64(struct segment_command_64 *seg, const char *name);
struct load_command *find_load_command(struct mach_header_64 *mh, uint32_t cmd);

typedef struct lsym_map {
    void* map;
    const char* path;
    size_t sz;
} lsym_map_t;

typedef enum {
    LSYM_DO_NOT_REBASE = (1 << 0)
} lsym_gadget_flags;

typedef uint64_t lsym_map_pointer_t;
typedef uint64_t lsym_kern_pointer_t;
typedef uint64_t lsym_slidden_kern_pointer_t;
typedef uint64_t lsym_offset_t;

lsym_kern_pointer_t         kext_pointer(const char* identifier);
lsym_map_t                 *lsym_map_file(const char *path);
lsym_kern_pointer_t         lsym_find_symbol(lsym_map_t *mapping, const char *name);
lsym_kern_pointer_t         lsym_find_gadget(lsym_map_t *mapping, const char *bytes, const uint32_t size, const lsym_gadget_flags flags);
lsym_kern_pointer_t         lsym_kernel_base(lsym_map_t *mapping);
lsym_slidden_kern_pointer_t lsym_slide_pointer(lsym_kern_pointer_t pointer);
lsym_offset_t               lsym_vm_addrperm();

typedef struct kernel_exploit_vector kernel_exploit_vector_t;

#endif /* defined(__pwn__lsym__) */
