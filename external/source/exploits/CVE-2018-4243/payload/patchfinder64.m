
//
//  patchfinder64.c
//  extra_recipe
//
//  Created by xerub on 06/06/2017.
//  Copyright © 2017 xerub. All rights reserved.
//

#import <assert.h>
#import <stdint.h>
#import <string.h>
#import "kernel_utils.h"

typedef unsigned long long addr_t;

#define IS64(image) (*(uint8_t *)(image) & 1)

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

/* generic stuff *************************************************************/

#define UCHAR_MAX 255

static unsigned char *
Boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */
    
    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;
    
    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;
    
    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;
    
    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;
    
    /* ---- Do the matching ---- */
    
    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;
        
        /* otherwise, we need to skip some bytes and start again.
         Note that here we are getting the skip value based on the last byte
         of needle, no matter where we didn't match. So if needle is: "abcd"
         then we are skipping based on 'd' and that value will be 4, and
         for "abcdd" we again skip on 'd' but the value will be only 1.
         The alternative of pretending that the mismatched character was
         the last character is slower in the normal case (E.g. finding
         "abcd" in "...azcd..." gives 4 by using 'd' but only
         4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }
    
    return NULL;
}

/* disassembler **************************************************************/

static int HighestSetBit(int N, uint32_t imm)
{
    int i;
    for (i = N - 1; i >= 0; i--) {
        if (imm & (1 << i)) {
            return i;
        }
    }
    return -1;
}

static uint64_t ZeroExtendOnes(unsigned M, unsigned N)    // zero extend M ones to N width
{
    (void)N;
    return ((uint64_t)1 << M) - 1;
}

static uint64_t RORZeroExtendOnes(unsigned M, unsigned N, unsigned R)
{
    uint64_t val = ZeroExtendOnes(M, N);
    if (R == 0) {
        return val;
    }
    return ((val >> R) & (((uint64_t)1 << (N - R)) - 1)) | ((val & (((uint64_t)1 << R) - 1)) << (N - R));
}

static uint64_t Replicate(uint64_t val, unsigned bits)
{
    uint64_t ret = val;
    unsigned shift;
    for (shift = bits; shift < 64; shift += bits) {    // XXX actually, it is either 32 or 64
        ret |= (val << shift);
    }
    return ret;
}

static int DecodeBitMasks(unsigned immN, unsigned imms, unsigned immr, int immediate, uint64_t *newval)
{
    unsigned levels, S, R, esize;
    int len = HighestSetBit(7, (immN << 6) | (~imms & 0x3F));
    if (len < 1) {
        return -1;
    }
    levels = ZeroExtendOnes(len, 6);
    if (immediate && (imms & levels) == levels) {
        return -1;
    }
    S = imms & levels;
    R = immr & levels;
    esize = 1 << len;
    *newval = Replicate(RORZeroExtendOnes(S + 1, esize, R), esize);
    return 0;
}

static int DecodeMov(uint32_t opcode, uint64_t total, int first, uint64_t *newval)
{
    unsigned o = (opcode >> 29) & 3;
    unsigned k = (opcode >> 23) & 0x3F;
    unsigned rn, rd;
    uint64_t i;
    
    if (k == 0x24 && o == 1) {            // MOV (bitmask imm) <=> ORR (immediate)
        unsigned s = (opcode >> 31) & 1;
        unsigned N = (opcode >> 22) & 1;
        if (s == 0 && N != 0) {
            return -1;
        }
        rn = (opcode >> 5) & 0x1F;
        if (rn == 31) {
            unsigned imms = (opcode >> 10) & 0x3F;
            unsigned immr = (opcode >> 16) & 0x3F;
            return DecodeBitMasks(N, imms, immr, 1, newval);
        }
    } else if (k == 0x25) {                // MOVN/MOVZ/MOVK
        unsigned s = (opcode >> 31) & 1;
        unsigned h = (opcode >> 21) & 3;
        if (s == 0 && h > 1) {
            return -1;
        }
        i = (opcode >> 5) & 0xFFFF;
        h *= 16;
        i <<= h;
        if (o == 0) {                // MOVN
            *newval = ~i;
            return 0;
        } else if (o == 2) {            // MOVZ
            *newval = i;
            return 0;
        } else if (o == 3 && !first) {        // MOVK
            *newval = (total & ~((uint64_t)0xFFFF << h)) | i;
            return 0;
        }
    } else if ((k | 1) == 0x23 && !first) {        // ADD (immediate)
        unsigned h = (opcode >> 22) & 3;
        if (h > 1) {
            return -1;
        }
        rd = opcode & 0x1F;
        rn = (opcode >> 5) & 0x1F;
        if (rd != rn) {
            return -1;
        }
        i = (opcode >> 10) & 0xFFF;
        h *= 12;
        i <<= h;
        if (o & 2) {                // SUB
            *newval = total - i;
            return 0;
        } else {                // ADD
            *newval = total + i;
            return 0;
        }
    }
    
    return -1;
}

/* patchfinder ***************************************************************/

static addr_t
Step64(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start + length;
    while (start < end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start += 4;
    }
    return 0;
}

// str8 = Step64_back(Kernel, ref, ref - bof, INSN_STR8);
static addr_t
Step64_back(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start - length;
    while (start >= end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start -= 4;
    }
    return 0;
}

// Finds start of function
static addr_t
BOF64(const uint8_t *buf, addr_t start, addr_t where)
{
    for (; where >= start; where -= 4) {
        uint32_t op = *(uint32_t *)(buf + where);
        if ((op & 0xFFC003FF) == 0x910003FD) {
            unsigned delta = (op >> 10) & 0xFFF;
            //printf("%x: ADD X29, SP, #0x%x\n", where, delta);
            if ((delta & 0xF) == 0) {
                addr_t prev = where - ((delta >> 4) + 1) * 4;
                uint32_t au = *(uint32_t *)(buf + prev);
                if ((au & 0xFFC003E0) == 0xA98003E0) {
                    //printf("%x: STP x, y, [SP,#-imm]!\n", prev);
                    return prev;
                }
            }
        }
    }
    return 0;
}

static addr_t
xref64(const uint8_t *buf, addr_t start, addr_t end, addr_t what)
{
    addr_t i;
    uint64_t value[32];
    
    memset(value, 0, sizeof(value));
    
    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
             unsigned rd = op & 0x1F;
             unsigned rm = (op >> 16) & 0x1F;
             //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
             value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;            // XXX not counted as true xref
            value[reg] = value[rn] + imm;    // XXX address, not actual value
            /*} else if ((op & 0xF9C00000) == 0xF9000000) {
             unsigned rn = (op >> 5) & 0x1F;
             unsigned imm = ((op >> 10) & 0xFFF) << 3;
             //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
             if (!imm) continue;            // XXX not counted as true xref
             value[rn] = value[rn] + imm;    // XXX address, not actual value*/
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;        // XXX address, not actual value
        }
        if (value[reg] == what) {
            return i;
        }
    }
    return 0;
}

static addr_t
Calc64(const uint8_t *buf, addr_t start, addr_t end, int which)
{
    addr_t i;
    uint64_t value[32];
    
    memset(value, 0, sizeof(value));
    
    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
             unsigned rd = op & 0x1F;
             unsigned rm = (op >> 16) & 0x1F;
             //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
             value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;            // XXX not counted as true xref
            value[reg] = value[rn] + imm;    // XXX address, not actual value
        } else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;            // XXX not counted as true xref
            value[rn] = value[rn] + imm;    // XXX address, not actual value
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;        // XXX address, not actual value
        }
    }
    return value[which];
}

static addr_t
Calc64mov(const uint8_t *buf, addr_t start, addr_t end, int which)
{
    addr_t i;
    uint64_t value[32];
    
    memset(value, 0, sizeof(value));
    
    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        uint64_t newval;
        int rv = DecodeMov(op, value[reg], 0, &newval);
        if (rv == 0) {
            if (((op >> 31) & 1) == 0) {
                newval &= 0xFFFFFFFF;
            }
            value[reg] = newval;
        }
    }
    return value[which];
}

static addr_t
Find_call64(const uint8_t *buf, addr_t start, size_t length)
{
    return Step64(buf, start, length, 0x94000000, 0xFC000000);
}

static addr_t
Follow_call64(const uint8_t *buf, addr_t call)
{
    long long w;
    w = *(uint32_t *)(buf + call) & 0x3FFFFFF;
    w <<= 64 - 26;
    w >>= 64 - 26 - 2;
    return call + w;
}

static addr_t
Follow_cbz(const uint8_t *buf, addr_t cbz)
{
    return cbz + ((*(int *)(buf + cbz) & 0x3FFFFE0) << 10 >> 13);
}

/* kernel iOS10 **************************************************************/

#import <fcntl.h>
#import <stdio.h>
#import <stdlib.h>
#import <unistd.h>
#import <mach-o/loader.h>

//#define __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__

#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
#import <mach/mach.h>
size_t KernelRead(uint64_t where, void *p, size_t size);
#endif

static uint8_t *Kernel = NULL;
static size_t Kernel_size = 0;

static addr_t XNUCore_Base = 0;
static addr_t XNUCore_Size = 0;
static addr_t Prelink_Base = 0;
static addr_t Prelink_Size = 0;
static addr_t CString_base = 0;
static addr_t CString_size = 0;
static addr_t PString_base = 0;
static addr_t PString_size = 0;
static addr_t KernDumpBase = -1;
static addr_t Kernel_entry = 0;
static void *Kernel_mh = 0;
static addr_t Kernel_delta = 0;

int
InitPatchfinder(addr_t base, const char *filename)
{
    size_t rv;
    uint8_t buf[0x4000];
    unsigned i, j;
    const struct mach_header *hdr = (struct mach_header *)buf;
    const uint8_t *q;
    addr_t min = -1;
    addr_t max = 0;
    int is64 = 0;
    
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
#define close(f)
    rv = KernelRead(base, buf, sizeof(buf));
    if (rv != sizeof(buf)) {
        return -1;
    }
#else    /* __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ */
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    rv = read(fd, buf, sizeof(buf));
    if (rv != sizeof(buf)) {
        close(fd);
        return -1;
    }
#endif    /* __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ */
    
    if (!MACHO(buf)) {
        close(fd);
        return -1;
    }
    
    if (IS64(buf)) {
        is64 = 4;
    }
    
    q = buf + sizeof(struct mach_header) + is64;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (min > seg->vmaddr) {
                min = seg->vmaddr;
            }
            if (max < seg->vmaddr + seg->vmsize) {
                max = seg->vmaddr + seg->vmsize;
            }
            if (!strcmp(seg->segname, "__TEXT_EXEC")) {
                XNUCore_Base = seg->vmaddr;
                XNUCore_Size = seg->filesize;
            }
            if (!strcmp(seg->segname, "__PLK_TEXT_EXEC")) {
                Prelink_Base = seg->vmaddr;
                Prelink_Size = seg->filesize;
            }
            if (!strcmp(seg->segname, "__TEXT")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__cstring")) {
                        CString_base = sec[j].addr;
                        CString_size = sec[j].size;
                    }
                }
            }
            if (!strcmp(seg->segname, "__PRELINK_TEXT")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__text")) {
                        PString_base = sec[j].addr;
                        PString_size = sec[j].size;
                    }
                }
            }
            if (!strcmp(seg->segname, "__LINKEDIT")) {
                Kernel_delta = seg->vmaddr - min - seg->fileoff;
            }
        }
        if (cmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(cmd + 1);
            uint32_t flavor = ptr[0];
            struct {
                uint64_t x[29];    /* General purpose registers x0-x28 */
                uint64_t fp;    /* Frame pointer x29 */
                uint64_t lr;    /* Link register x30 */
                uint64_t sp;    /* Stack pointer x31 */
                uint64_t pc;     /* Program counter */
                uint32_t cpsr;    /* Current program status register */
            } *thread = (void *)(ptr + 2);
            if (flavor == 6) {
                Kernel_entry = thread->pc;
            }
        }
        q = q + cmd->cmdsize;
    }
    
    KernDumpBase = min;
    XNUCore_Base -= KernDumpBase;
    Prelink_Base -= KernDumpBase;
    CString_base -= KernDumpBase;
    PString_base -= KernDumpBase;
    Kernel_size = max - min;
    
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
    Kernel = malloc(Kernel_size);
    if (!Kernel) {
        return -1;
    }
    rv = KernelRead(KernDumpBase, Kernel, Kernel_size);
    if (rv != Kernel_size) {
        free(Kernel);
        return -1;
    }
    
    Kernel_mh = Kernel + base - min;
    
    (void)filename;
#undef close
#else    /* __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ */
    Kernel = calloc(1, Kernel_size);
    if (!Kernel) {
        close(fd);
        return -1;
    }
    
    q = buf + sizeof(struct mach_header) + is64;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            size_t sz = pread(fd, Kernel + seg->vmaddr - min, seg->filesize, seg->fileoff);
            if (sz != seg->filesize) {
                close(fd);
                free(Kernel);
                return -1;
            }
            if (!Kernel_mh) {
                Kernel_mh = Kernel + seg->vmaddr - min;
            }
            printf("%s\n", seg->segname);
            if (!strcmp(seg->segname, "__LINKEDIT")) {
                Kernel_delta = seg->vmaddr - min - seg->fileoff;
            }
        }
        q = q + cmd->cmdsize;
    }
    
    close(fd);
    
    (void)base;
#endif    /* __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ */
    return 0;
}

void
TermPatchfinder(void)
{
    free(Kernel);
}

/* these operate on VA ******************************************************/

#define INSN_RET  0xD65F03C0, 0xFFFFFFFF
#define INSN_CALL 0x94000000, 0xFC000000
#define INSN_B    0x14000000, 0xFC000000
#define INSN_CBZ  0x34000000, 0xFC000000
#define INSN_ADRP 0x90000000, 0x9F000000

addr_t
Find_register_value(addr_t where, int reg)
{
    addr_t val;
    addr_t bof = 0;
    where -= KernDumpBase;
    if (where > XNUCore_Base) {
        bof = BOF64(Kernel, XNUCore_Base, where);
        if (!bof) {
            bof = XNUCore_Base;
        }
    } else if (where > Prelink_Base) {
        bof = BOF64(Kernel, Prelink_Base, where);
        if (!bof) {
            bof = Prelink_Base;
        }
    }
    val = Calc64(Kernel, bof, where, reg);
    if (!val) {
        return 0;
    }
    return val + KernDumpBase;
}

addr_t
Find_reference(addr_t to, int n, int prelink)
{
    addr_t ref, end;
    addr_t base = XNUCore_Base;
    addr_t size = XNUCore_Size;
    if (prelink) {
        base = Prelink_Base;
        size = Prelink_Size;
    }
    if (n <= 0) {
        n = 1;
    }
    end = base + size;
    to -= KernDumpBase;
    do {
        ref = xref64(Kernel, base, end, to);
        if (!ref) {
            return 0;
        }
        base = ref + 4;
    } while (--n > 0);
    return ref + KernDumpBase;
}

addr_t
Find_strref(const char *string, int n, int prelink)
{
    uint8_t *str;
    addr_t base = CString_base;
    addr_t size = CString_size;
    if (prelink) {
        base = PString_base;
        size = PString_size;
    }
    str = Boyermoore_horspool_memmem(Kernel + base, size, (uint8_t *)string, strlen(string));
    if (!str) {
        return 0;
    }
    return Find_reference(str - Kernel + KernDumpBase, n, prelink);
}

/****** fun *******/

addr_t Find_add_x0_x0_0x40_ret(void) {
    addr_t off;
    uint32_t *k;
    k = (uint32_t *)(Kernel + XNUCore_Base);
    for (off = 0; off < XNUCore_Size - 4; off += 4, k++) {
        if (k[0] == 0x91010000 && k[1] == 0xD65F03C0) {
            return off + XNUCore_Base + KernDumpBase;
        }
    }
    k = (uint32_t *)(Kernel + Prelink_Base);
    for (off = 0; off < Prelink_Size - 4; off += 4, k++) {
        if (k[0] == 0x91010000 && k[1] == 0xD65F03C0) {
            return off + Prelink_Base + KernDumpBase;
        }
    }
    return 0;
}

uint64_t Find_allproc(void) {
    // Find the first reference to the string
    addr_t ref = Find_strref("\"pgrp_add : pgrp is dead adding process\"", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= KernDumpBase;
    
    uint64_t start = BOF64(Kernel, XNUCore_Base, ref);
    if (!start) {
        return 0;
    }
    
    // Find AND W8, W8, #0xFFFFDFFF - it's a pretty distinct instruction
    addr_t weird_instruction = 0;
    for (int i = 4; i < 4*0x100; i+=4) {
        uint32_t op = *(uint32_t *)(Kernel + ref + i);
        if (op == 0x12127908) {
            weird_instruction = ref+i;
            break;
        }
    }
    if (!weird_instruction) {
        return 0;
    }
    
    uint64_t val = Calc64(Kernel, start, weird_instruction - 8, 8);
    if (!val) {
        printf("Failed to calculate x8");
        return 0;
    }
    
    return val + KernDumpBase;
}

uint64_t Find_copyout(void) {
    // Find the first reference to the string
    addr_t ref = Find_strref("\"%s(%p, %p, %lu) - transfer too large\"", 2, 0);
    if (!ref) {
        return 0;
    }
    ref -= KernDumpBase;
    
    uint64_t start = 0;
    for (int i = 4; i < 0x100*4; i+=4) {
        uint32_t op = *(uint32_t*)(Kernel+ref-i);
        if (op == 0xd10143ff) { // SUB SP, SP, #0x50
            start = ref-i;
            break;
        }
    }
    if (!start) {
        return 0;
    }
    
    return start + KernDumpBase;
}

uint64_t Find_bzero(void) {
    // Just find SYS #3, c7, c4, #1, X3, then get the start of that function
    addr_t off;
    uint32_t *k;
    k = (uint32_t *)(Kernel + XNUCore_Base);
    for (off = 0; off < XNUCore_Size - 4; off += 4, k++) {
        if (k[0] == 0xd50b7423) {
            off += XNUCore_Base;
            break;
        }
    }
    
    uint64_t start = BOF64(Kernel, XNUCore_Base, off);
    if (!start) {
        return 0;
    }
    
    return start + KernDumpBase;
}

addr_t Find_bcopy(void) {
    // Jumps straight into memmove after switching x0 and x1 around
    // Guess we just find the switch and that's it
    addr_t off;
    uint32_t *k;
    k = (uint32_t *)(Kernel + XNUCore_Base);
    for (off = 0; off < XNUCore_Size - 4; off += 4, k++) {
        if (k[0] == 0xAA0003E3 && k[1] == 0xAA0103E0 && k[2] == 0xAA0303E1 && k[3] == 0xd503201F) {
            return off + XNUCore_Base + KernDumpBase;
        }
    }
    k = (uint32_t *)(Kernel + Prelink_Base);
    for (off = 0; off < Prelink_Size - 4; off += 4, k++) {
        if (k[0] == 0xAA0003E3 && k[1] == 0xAA0103E0 && k[2] == 0xAA0303E1 && k[3] == 0xd503201F) {
            return off + Prelink_Base + KernDumpBase;
        }
    }
    return 0;
}

uint64_t Find_rootvnode(void) {
    // Find the first reference to the string
    addr_t ref = Find_strref("/var/run/.vfs_rsrc_streams_%p%x", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= KernDumpBase;
    
    uint64_t start = BOF64(Kernel, XNUCore_Base, ref);
    if (!start) {
        return 0;
    }
    
    // Find MOV X9, #0x2000000000 - it's a pretty distinct instruction
    addr_t weird_instruction = 0;
    for (int i = 4; i < 4*0x100; i+=4) {
        uint32_t op = *(uint32_t *)(Kernel + ref - i);
        if (op == 0xB25B03E9) {
            weird_instruction = ref-i;
            break;
        }
    }
    if (!weird_instruction) {
        return 0;
    }
    
    uint64_t val = Calc64(Kernel, start, weird_instruction, 8);
    if (!val) {
        return 0;
    }
    
    return val + KernDumpBase;
}


addr_t Find_vnode_lookup() {
    addr_t call, bof;
    addr_t ref = Find_strref("/private/var/mobile", 0, 0);
    if (!ref) {
        return 0;
    }
    ref -= KernDumpBase;
    bof = BOF64(Kernel, XNUCore_Base, ref);
    if (!bof) {
        return 0;
    }
    call = Step64(Kernel, ref, ref - bof, INSN_CALL);
    if (!call) {
        return 0;
    }
    call += 4;
    call = Step64(Kernel, call, call - bof, INSN_CALL);
    if (!call) {
        return 0;
    }
    call += 4;
    call = Step64(Kernel, call, call - bof, INSN_CALL);
    if (!call) {
        return 0;
    }
    return Follow_call64(Kernel, call) + KernDumpBase;
}

addr_t Find_trustcache(void) {
    addr_t call, func;
    addr_t ref = Find_strref("%s: only allowed process can check the trust cache", 1, 1);
    if (!ref) {
        return 0;
    }
    ref -= KernDumpBase;
    call = Step64_back(Kernel, ref, 44, INSN_CALL);
    if (!call) {
        return 0;
    }
    func = Follow_call64(Kernel, call);
    if (!func) {
        return 0;
    }
    call = Step64(Kernel, func, 32, INSN_CALL);
    if (!call) {
        return 0;
    }
    func = Follow_call64(Kernel, call);
    if (!func) {
        return 0;
    }
    call = Step64(Kernel, func, 32, INSN_CALL);
    if (!call) {
        return 0;
    }
    call = Step64(Kernel, call + 4, 32, INSN_CALL);
    if (!call) {
        return 0;
    }
    func = Follow_call64(Kernel, call);
    if (!func) {
        return 0;
    }
    call = Step64(Kernel, func, 48, INSN_CALL);
    if (!call) {
        return 0;
    }
    uint64_t val = Calc64(Kernel, call, call + 24, 21);
    if (!val) {
        // iOS 12
        ref = Find_strref("\"loadable trust cache buffer too small (%ld) for entries claimed (%d)\"", 1, 0);
        if (!ref) {
            return 0;
        }
        ref -= KernDumpBase;
        
        val = Calc64(Kernel, ref-12*4, ref-12*4+12, 8);
        if (!val) {
            return 0;
        }
        return val + KernDumpBase;
    }
    return val + KernDumpBase;
}

// people that worked in unc0ver. sparkey maybe?
addr_t Find_amficache() {
    uint64_t cbz, call, func, val;
    uint64_t ref = Find_strref("amfi_prevent_old_entitled_platform_binaries", 1, 1);
    if (!ref) {
        // iOS 11
        ref = Find_strref("com.apple.MobileFileIntegrity", 0, 1);
        if (!ref) {
            return 0;
        }
        ref -= KernDumpBase;
        call = Step64(Kernel, ref, 64, INSN_CALL);
        if (!call) {
            return 0;
        }
        call = Step64(Kernel, call + 4, 64, INSN_CALL);
        goto okay;
    }
    ref -= KernDumpBase;
    cbz = Step64(Kernel, ref, 32, INSN_CBZ);
    if (!cbz) {
        return 0;
    }
    call = Step64(Kernel, Follow_cbz(Kernel, cbz), 4, INSN_CALL);
okay:
    if (!call) {
        return 0;
    }
    func = Follow_call64(Kernel, call);
    if (!func) {
        return 0;
    }
    val = Calc64(Kernel, func, func + 16, 8);
    if (!val) {
        ref = Find_strref("%s: only allowed process can check the trust cache", 1, 1); // Trying to find AppleMobileFileIntegrityUserClient::isCdhashInTrustCache
        if (!ref) {
            return 0;
        }
        ref -= KernDumpBase;
        call = Step64_back(Kernel, ref, 11*4, INSN_CALL);
        if (!call) {
            return 0;
        }
        func = Follow_call64(Kernel, call);
        if (!func) {
            return 0;
        }
        call = Step64(Kernel, func, 8*4, INSN_CALL);
        if (!call) {
            return 0;
        }
        func = Follow_call64(Kernel, call);
        if (!func) {
            return 0;
        }
        call = Step64(Kernel, func, 8*4, INSN_CALL);
        if (!call) {
            return 0;
        }
        call = Step64(Kernel, call+4, 8*4, INSN_CALL);
        if (!call) {
            return 0;
        }
        func = Follow_call64(Kernel, call);
        if (!func) {
            return 0;
        }
        call = Step64(Kernel, func, 12*4, INSN_CALL);
        if (!call) {
            return 0;
        }
        
        val = Calc64(Kernel, call, call + 6*4, 21);
    }
    return val + KernDumpBase;
}


addr_t Find_zone_map_ref(void) {
    // \"Nothing being freed to the zone_map. start = end = %p\\n\"
    uint64_t val = KernDumpBase;
    
    addr_t ref = Find_strref("\"Nothing being freed to the zone_map. start = end = %p\\n\"", 1, 0);
    ref -= KernDumpBase;
    
    // skip add & adrp for panic str
    ref -= 8;
    
    // adrp xX, #_zone_map@PAGE
    ref = Step64_back(Kernel, ref, 30, INSN_ADRP);
    
    uint32_t *insn = (uint32_t*)(Kernel+ref);
    // get pc
    val += ((uint8_t*)(insn) - Kernel) & ~0xfff;
    uint8_t xm = *insn & 0x1f;
    
    // don't ask, I wrote this at 5am
    val += (*insn<<9 & 0x1ffffc000) | (*insn>>17 & 0x3000);
    
    // ldr x, [xX, #_zone_map@PAGEOFF]
    ++insn;
    if ((*insn & 0xF9C00000) != 0xF9400000) {
        return 0;
    }
    
    // xd == xX, xn == xX,
    if ((*insn&0x1f) != xm || ((*insn>>5)&0x1f) != xm) {
        return 0;
    }
    
    val += ((*insn >> 10) & 0xFFF) << 3;
    
    return val;
}

addr_t Find_OSBoolean_True() {
    addr_t val;
    addr_t ref = Find_strref("Delay Autounload", 0, 0);
    if (!ref) {
        return 0;
    }
    ref -= KernDumpBase;
    
    addr_t weird_instruction = 0;
    for (int i = 4; i < 4*0x100; i+=4) {
        uint32_t op = *(uint32_t *)(Kernel + ref + i);
        if (op == 0x320003E0) {
            weird_instruction = ref+i;
            break;
        }
    }
    if (!weird_instruction) {
        return 0;
    }
    
    val = Calc64(Kernel, ref, weird_instruction, 8);
    if (!val) {
        return 0;
    }
    
    return KernelRead_64bits(val + KernDumpBase);
}

addr_t Find_OSBoolean_False() {
    return Find_OSBoolean_True()+8;
}
addr_t Find_osunserializexml() {
    addr_t ref = Find_strref("OSUnserializeXML: %s near line %d\n", 1, 0);
    ref -= KernDumpBase;
    uint64_t start = BOF64(Kernel, XNUCore_Base, ref);
    return start + KernDumpBase;
}

addr_t Find_smalloc() {
    addr_t ref = Find_strref("sandbox memory allocation failure", 1, 1);
    ref -= KernDumpBase;
    uint64_t start = BOF64(Kernel, Prelink_Base, ref);
    return start + KernDumpBase;
}

addr_t Find_sbops() {
    addr_t off, what;
    uint8_t *str = Boyermoore_horspool_memmem(Kernel + PString_base, PString_size, (uint8_t *)"Seatbelt sandbox policy", sizeof("Seatbelt sandbox policy") - 1);
    if (!str) {
        return 0;
    }
    what = str - Kernel + KernDumpBase;
    for (off = 0; off < Kernel_size - Prelink_Base; off += 8) {
        if (*(uint64_t *)(Kernel + Prelink_Base + off) == what) {
            return *(uint64_t *)(Kernel + Prelink_Base + off + 24);
        }
    }
    return 0;
}

uint64_t Find_bootargs(void) {
    
    /*
     ADRP            X8, #_PE_state@PAGE
     ADD             X8, X8, #_PE_state@PAGEOFF
     LDR             X8, [X8,#(PE_state__boot_args - 0xFFFFFFF0078BF098)]
     ADD             X8, X8, #0x6C
     STR             X8, [SP,#0x550+var_550]
     ADRP            X0, #aBsdInitCannotF@PAGE ; "\"bsd_init: cannot find root vnode: %s"...
     ADD             X0, X0, #aBsdInitCannotF@PAGEOFF ; "\"bsd_init: cannot find root vnode: %s"...
     BL              _panic
     */
    
    addr_t ref = Find_strref("\"bsd_init: cannot find root vnode: %s\"", 1, 0);
    
    if (ref == 0) {
        return 0;
    }
    
    ref -= KernDumpBase;
    // skip add & adrp for panic str
    ref -= 8;
    uint32_t *insn = (uint32_t*)(Kernel+ref);
    
    // skip str
    --insn;
    // add xX, xX, #cmdline_offset
    uint8_t xm = *insn&0x1f;
    if (((*insn>>5)&0x1f) != xm || ((*insn>>22)&3) != 0) {
        return 0;
    }
    
    //cmdline_offset = (*insn>>10) & 0xfff;
    
    uint64_t val = KernDumpBase;
    
    --insn;
    // ldr xX, [xX, #(PE_state__boot_args - PE_state)]
    if ((*insn & 0xF9C00000) != 0xF9400000) {
        return 0;
    }
    // xd == xX, xn == xX,
    if ((*insn&0x1f) != xm || ((*insn>>5)&0x1f) != xm) {
        return 0;
    }
    
    val += ((*insn >> 10) & 0xFFF) << 3;
    
    --insn;
    // add xX, xX, #_PE_state@PAGEOFF
    if ((*insn&0x1f) != xm || ((*insn>>5)&0x1f) != xm || ((*insn>>22)&3) != 0) {
        return 0;
    }
    
    val += (*insn>>10) & 0xfff;
    
    --insn;
    if ((*insn & 0x1f) != xm) {
        return 0;
    }
    
    // pc
    val += ((uint8_t*)(insn) - Kernel) & ~0xfff;
    
    // don't ask, I wrote this at 5am
    val += (*insn<<9 & 0x1ffffc000) | (*insn>>17 & 0x3000);
    
    return val;
}

