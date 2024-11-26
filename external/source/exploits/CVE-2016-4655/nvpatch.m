/*
 * nvpatch.m - Patch kernel to unrestrict NVRAM variables
 *             Taken and modified from kern-utils
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016 Pupyshev Nikita
 * Copyright (c) 2017 Siguza
 */

#include <errno.h>              // errno
#include <stdio.h>              // fprintf, stderr
#include <stdlib.h>             // free, malloc
#include <string.h>             // memmem, strcmp, strnlen

#include "arch.h"               // ADDR, MACH_*, mach_*
#include "mach-o.h"             // CMD_ITERATE

#include "nvpatch.h"

#define STRING_SEG  "__TEXT"
#define STRING_SEC  "__cstring"
#define OFVAR_SEG   "__DATA"
#define OFVAR_SEC   "__data"

enum
{
    kOFVarTypeBoolean = 1,
    kOFVarTypeNumber,
    kOFVarTypeString,
    kOFVarTypeData,
};

enum
{
    kOFVarPermRootOnly = 0,
    kOFVarPermUserRead,
    kOFVarPermUserWrite,
    kOFVarPermKernelOnly,
};

typedef struct
{
    vm_address_t name;
    uint32_t type;
    uint32_t perm;
    int32_t offset;
} OFVar;

#define MAX_CHUNK_SIZE 0xFFF /* MIG limitation */

static vm_size_t kernel_read(task_t kernel_task, vm_address_t addr, vm_size_t size, void *buf)
{
    kern_return_t ret;
    vm_size_t remainder = size,
              bytes_read = 0;

    // The vm_* APIs are part of the mach_vm subsystem, which is a MIG thing
    // and therefore has a hard limit of 0x1000 bytes that it accepts. Due to
    // this, we have to do both reading and writing in chunks smaller than that.
    for(vm_address_t end = addr + size; addr < end; remainder -= size)
    {
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
        ret = vm_read_overwrite(kernel_task, addr, size, (vm_address_t)&((char*)buf)[bytes_read], &size);
        if(ret != KERN_SUCCESS || size == 0)
        {
            LOG("vm_read error: %s", mach_error_string(ret));
            break;
        }
        bytes_read += size;
        addr += size;
    }

    return bytes_read;
}

static vm_size_t kernel_write(task_t kernel_task, vm_address_t addr, vm_size_t size, void *buf)
{
    kern_return_t ret;
    vm_size_t remainder = size,
              bytes_written = 0;

    for(vm_address_t end = addr + size; addr < end; remainder -= size)
    {
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
        ret = vm_write(kernel_task, addr, (vm_offset_t)&((char*)buf)[bytes_written], (mach_msg_type_number_t)size);
        if(ret != KERN_SUCCESS)
        {
            LOG("vm_write error: %s", mach_error_string(ret));
            break;
        }
        bytes_written += size;
        addr += size;
    }

    return bytes_written;
}

int nvpatch(task_t kernel_task, vm_address_t kbase, const char *target)
{
    mach_hdr_t *hdr = malloc(MAX_HEADER_SIZE);
    if(hdr == NULL)
    {
        LOG("Failed to allocate header buffer (%s)", strerror(errno));
        return -1;
    }
    memset(hdr, 0, MAX_HEADER_SIZE);

    LOG("Reading kernel header...");
    if(kernel_read(kernel_task, kbase, MAX_HEADER_SIZE, hdr) != MAX_HEADER_SIZE)
    {
        LOG("Kernel I/O error");
        return -1;
    }

    segment_t
    cstring =
    {
        .addr = 0,
        .len = 0,
        .buf = NULL,
    },
    data =
    {
        .addr = 0,
        .len = 0,
        .buf = NULL,
    };
    CMD_ITERATE(hdr, cmd)
    {
        switch(cmd->cmd)
        {
            case MACH_LC_SEGMENT:
                {
                    mach_seg_t *seg = (mach_seg_t*)cmd;
                    mach_sec_t *sec = (mach_sec_t*)(seg + 1);
                    for(size_t i = 0; i < seg->nsects; ++i)
                    {
                        if(strcmp(sec[i].segname, STRING_SEG) == 0 && strcmp(sec[i].sectname, STRING_SEC) == 0)
                        {
                            LOG("Found " STRING_SEG "." STRING_SEC " section at " ADDR, (vm_address_t)sec[i].addr);
                            cstring.addr = sec[i].addr;
                            cstring.len = sec[i].size;
                            cstring.buf = malloc(cstring.len);
                            if(cstring.buf == NULL)
                            {
                                LOG("Failed to allocate section buffer (%s)", strerror(errno));
                                return -1;
                            }
                            if(kernel_read(kernel_task, cstring.addr, cstring.len, cstring.buf) != cstring.len)
                            {
                                LOG("Kernel I/O error");
                                return -1;
                            }
                        }
                        else if(strcmp(sec[i].segname, OFVAR_SEG) == 0 && strcmp(sec[i].sectname, OFVAR_SEC) == 0)
                        {
                            LOG("Found " OFVAR_SEG "." OFVAR_SEC " section at " ADDR, (vm_address_t)sec[i].addr);
                            data.addr = sec[i].addr;
                            data.len = sec[i].size;
                            data.buf = malloc(data.len);
                            if(data.buf == NULL)
                            {
                                LOG("Failed to allocate section buffer (%s)", strerror(errno));
                                return -1;
                            }
                            if(kernel_read(kernel_task, data.addr, data.len, data.buf) != data.len)
                            {
                                LOG("Kernel I/O error");
                                return -1;
                            }
                        }
                    }
                }
                break;
        }
    }
    if(cstring.buf == NULL)
    {
        LOG("Failed to find " STRING_SEG "." STRING_SEC " section");
        return -1;
    }
    if(data.buf == NULL)
    {
        LOG("Failed to find " OFVAR_SEG "." OFVAR_SEC " section");
        return -1;
    }

    // This is the name of the first NVRAM variable
    char first[] = "little-endian?";
    char *str = memmem(cstring.buf, cstring.len, first, sizeof(first));
    if(str == NULL)
    {
        LOG("Failed to find string \"%s\"", first);
        return -1;
    }
    vm_address_t str_addr = (str - cstring.buf) + cstring.addr;
    LOG("Found string \"%s\" at " ADDR, first, str_addr);

    // Now let's find a reference to it
    OFVar *gOFVars = NULL;
    for(vm_address_t *ptr = (vm_address_t*)data.buf, *end = (vm_address_t*)&data.buf[data.len]; ptr < end; ++ptr)
    {
        if(*ptr == str_addr)
        {
            gOFVars = (OFVar*)ptr;
            break;
        }
    }
    if(gOFVars == NULL)
    {
        LOG("Failed to find gOFVariables");
        return -1;
    }
    vm_address_t gOFAddr = ((char*)gOFVars - data.buf) + data.addr;
    LOG("Found gOFVariables at " ADDR, gOFAddr);

    // Sanity checks
    size_t numvars = 0,
           longest_name = 0;
    for(OFVar *var = gOFVars; (char*)var < &data.buf[data.len]; ++var)
    {
        if(var->name == 0) // End marker
        {
            break;
        }
        if(var->name < cstring.addr || var->name >= cstring.addr + cstring.len)
        {
            LOG("gOFVariables[%lu].name is out of bounds", numvars);
            return -1;
        }
        char *name = &cstring.buf[var->name - cstring.addr];
        size_t maxlen = cstring.len - (name - cstring.buf),
               namelen = strnlen(name, maxlen);
        if(namelen == maxlen)
        {
            LOG("gOFVariables[%lu].name exceeds __cstring size", numvars);
            return -1;
        }
        for(size_t i = 0; i < namelen; ++i)
        {
            if(name[i] < 0x20 || name[i] >= 0x7f)
            {
                LOG("gOFVariables[%lu].name contains non-printable character: 0x%02x", numvars, name[i]);
                return -1;
            }
        }
        longest_name = namelen > longest_name ? namelen : longest_name;
        switch(var->type)
        {
            case kOFVarTypeBoolean:
            case kOFVarTypeNumber:
            case kOFVarTypeString:
            case kOFVarTypeData:
                break;
            default:
                LOG("gOFVariables[%lu] has unknown type: 0x%x", numvars, var->type);
                return -1;
        }
        switch(var->perm)
        {
            case kOFVarPermRootOnly:
            case kOFVarPermUserRead:
            case kOFVarPermUserWrite:
            case kOFVarPermKernelOnly:
                break;
            default:
                LOG("gOFVariables[%lu] has unknown permissions: 0x%x", numvars, var->perm);
                return -1;
        }
        ++numvars;
    }
    if(numvars < 1)
    {
        LOG("gOFVariables contains zero entries");
        return -1;
    }

    for(size_t i = 0; i < numvars; ++i)
    {
        char *name = &cstring.buf[gOFVars[i].name - cstring.addr];
        if(strcmp(name, target) == 0)
        {
            if(gOFVars[i].perm != kOFVarPermKernelOnly)
            {
                LOG("Variable \"%s\" is already writable for %s", target, gOFVars[i].perm == kOFVarPermUserWrite ? "everyone" : "root");
                goto done;
            }
            vm_size_t off = ((char*)&gOFVars[i].perm) - data.buf;
            uint32_t newperm = kOFVarPermUserWrite; // was kOFVarPermRootOnly
            if(kernel_write(kernel_task, data.addr + off, sizeof(newperm), &newperm) != sizeof(newperm))
            {
                LOG("Kernel I/O error");
                return -1;
            }
            LOG("Successfully patched permissions for variable \"%s\"", target);
            goto done;
        }
    }
    LOG("Failed to find variable \"%s\"", target);
    return -1;

    done:;

    free(cstring.buf);
    free(data.buf);
    free(hdr);

    return 0;
}
