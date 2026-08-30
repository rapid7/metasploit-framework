/*
 * find.m - Minimal offsets finder
 *          Taken and modified from cl0ver
 *
 * Copyright (c) 2016-2017 Siguza
 */

#include <stdint.h>
#include <string.h>             // strlen, strerror, memcmp
#include <mach/mach.h>

#include "arch.h"
#include "nvpatch.h"
#include "find.h"

// imm = register plus immediate, lit = PC-relative literal

#define IS_RET(instr) ((instr) == 0xd65f03c0)
#define IS_BL(instr) (((instr) & 0xfc000000) == 0x94000000)
#define LDR_IMM(instr) (((instr) >> 7) & 0x7ff8)
// for all *_LIT: 26-bit sign extend and multiply by 4
#define LDR_LIT(instr) ((((int64_t)(instr) & 0xffffe0) << 40) >> 43)
#define ADR_LIT(instr) (((((int64_t)(instr) & 0xffffe0) << 40) >> 43) | (((instr) >> 29) & 3))
#define ADRP_LIT(instr) (ADR_LIT(instr) << 12)
#define ADD_LIT(instr) (((instr) & 0x3ffc00) >> 10)

static segment_t* ptr_segment(segment_t *segs, size_t numsegs, void *ptr)
{
    for(size_t i = 0; i < numsegs; ++i)
    {
        if((char*)segs[i].buf <= (char*)ptr && &((char*)segs[i].buf)[segs[i].len] > (char*)ptr)
        {
            return &segs[i];
        }
    }
    LOG("pointer out of range: " ADDR, (vm_address_t)ptr);
    return NULL;
}

static vm_address_t ptr_to_vmem(segment_t *segs, size_t numsegs, void *ptr)
{
    segment_t *seg = ptr_segment(segs, numsegs, ptr);
    if(!seg)
    {
        return 0;
    }
    return seg->addr + ((char*)ptr - (char*)seg->buf);
}

static vm_address_t vmem_find_bytes(segment_t *segs, size_t numsegs, void *search, size_t len, size_t granularity, char *name)
{
    for(size_t i = 0; i < numsegs; ++i)
    {
        for(size_t off = 0; off <= segs[i].len - len; off += granularity)
        {
            if(memcmp(&((char*)segs[i].buf)[off], search, len) == 0)
            {
                return segs[i].addr + off;
            }
        }
    }
    LOG("Failed to vmem_find_bytes: %s", name);
    return 0;
}

static vm_address_t vmem_find_str(segment_t *segs, size_t numsegs, char *str)
{
    return vmem_find_bytes(segs, numsegs, str, strlen(str) + 1, 1, str);
}

vm_address_t find_kernel_task(segment_t *text)
{
    LOG("Looking for kernel_task...");

    vm_address_t panic_info = vmem_find_str(text, 1, "aapl,panic-info");
    LOG("\"aapl,panic-info\" at " ADDR "...", panic_info);
    if(panic_info)
    {
        for(uint32_t *ptr = (uint32_t*)text->buf, *end = (uint32_t*)&((char*)ptr)[text->len]; ptr < end; ++ptr)
        {
            if((*ptr & 0x9f000000) == 0x10000000) // adr
            {
                vm_address_t pc = ptr_to_vmem(text, 1, ptr);
                if(pc)
                {
                    if(pc + ADR_LIT(*ptr) == panic_info) // adr Xn, "aapl,panic-info"
                    {
                        LOG("Found reference to \"aapl,panic-info\" at " ADDR, pc);
                        for(uint32_t *p = ptr - 1; p >= (uint32_t*)text->buf; --p)
                        {
                            if((*p & 0xffffffe0) == 0xd538d080) // mrs Xn, tpidr_el1
                            {
                                LOG("Last reference to tpidr_el1 before that is at " ADDR, ptr_to_vmem(text, 1, p));

                                size_t num_ldrs = 0;
                                uint32_t *last = NULL;
                                for(++p; p < ptr; ++p)
                                {
                                    if((*p & 0xff000000) == 0x58000000) // ldr with PC-relative offset
                                    {
                                        last = p;
                                        ++num_ldrs;
                                    }
                                }

                                if(num_ldrs == 1)
                                {
                                    pc = ptr_to_vmem(text, 1, last);
                                    if(pc)
                                    {
                                        vm_address_t ret = pc + LDR_LIT(*last);
                                        LOG("Found kernel_task symbol at " ADDR, ret);
                                        return ret;
                                    }
                                }
                                else
                                {
                                    LOG("Number of PC-relative ldr's between tpidr_el1 and panic-ref is != 1");
                                }
                                goto next; // "break" would trigger the message below
                            }
                        }
                        LOG("But found no reference to tpidr_el1 before that, looking for next reference to \"aapl,panic-info\"...");
                        next:;
                    }
                }
            }
        }
    }

    LOG("Failed to find kernel_task");
    return 0;
}

vm_address_t find_ipc_space_kernel(segment_t *text)
{
    LOG("Looking for ipc_space_kernel...");

    vm_address_t str = vmem_find_str(text, 1, "\"failed to create resume port\"");
    LOG("\"\"failed to create resume port\"\" at " ADDR "...", str);
    if(str)
    {
        // find either convert_task_suspension_token_to_port or task_suspend
        for(uint32_t *ptr = (uint32_t*)text->buf, *end = (uint32_t*)&((char*)ptr)[text->len]; ptr < end; ++ptr)
        {
            if
            (
                (ptr[0] & 0x9f000000) == 0x90000000 && // adrp
                (ptr[1] & 0xffc00000) == 0x91000000    // add with unshifted immediate
            )
            {
                vm_address_t pc = ptr_to_vmem(text, 1, ptr);
                if(pc)
                {
                    if((pc & 0xfffffffffffff000) + ADRP_LIT(ptr[0]) + ADD_LIT(ptr[1]) == str) // ref to our string
                    {
                        LOG("Found reference to \"\"failed to create resume port\"\" at " ADDR, pc);
                        for(uint32_t *p = ptr - 1, count = 0; p >= (uint32_t*)text->buf; --p)
                        {
                            if(IS_RET(*p))
                            {
                                if(count == 0) // panic() lies after ret;, thus skip 2
                                {
                                    ++count;
                                }
                                else
                                {
                                    ++p;
                                    LOG("Start of function is at " ADDR, ptr_to_vmem(text, 1, p));

                                    for(count = 0; p < ptr; ++p) // find second bl
                                    {
                                        if(IS_BL(*p))
                                        {
                                            if(count == 0)
                                            {
                                                ++count;
                                            }
                                            else
                                            {
                                                LOG("Second bl is at " ADDR, ptr_to_vmem(text, 1, p));
                                                if
                                                (
                                                    (p[-3] & 0x9f000000) == 0x90000000 && // adrp
                                                    (p[-2] & 0xffc00000) == 0x91000000 && // add with unshifted immediate
                                                    (p[-1] & 0xffc00000) == 0xf9400000    // ldr with immediate
                                                )
                                                {
                                                    pc = ptr_to_vmem(text, 1, p - 3);
                                                    if(pc)
                                                    {
                                                        vm_address_t ret = (pc & 0xfffffffffffff000) + ADRP_LIT(p[-3]) + ADD_LIT(p[-2]) + LDR_IMM(p[-1]);
                                                        LOG("Found ipc_space_kernel symbol at " ADDR, ret);
                                                        return ret;
                                                    }
                                                }
                                                else
                                                {
                                                    LOG("Didn't find expected instructions before bl...");
                                                }
                                                goto next; // "break" would trigger the message below
                                            }
                                        }
                                    }

                                    LOG("But found no two bl; after that, looking for next reference to \"\"failed to create resume port\"\"...");
                                    goto next;
                                }
                            }
                        }
                        LOG("But found no two ret; before that, looking for next reference to \"\"failed to create resume port\"\"...");
                        next:;
                    }
                }
            }
        }
    }

    LOG("Failed to find ipc_space_kernel");
    return 0;
}
