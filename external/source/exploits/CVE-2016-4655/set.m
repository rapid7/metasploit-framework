/*
 * set.m - High-level handler to set boot nonce
 *
 * Copyright (c) 2017 Siguza & tihmstar
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

#include "arch.h"
#include "exploit64.h"
#include "nvpatch.h"
#include "set.h"

static int party_hard(void)
{
    int ret = 0;
    if(getuid() != 0) // Skip if we got root already
    {
        ret = -1;
        vm_address_t kbase = 0;
        task_t kernel_task = get_kernel_task(&kbase);
        LOG("kernel_task: 0x%x", kernel_task);
        if(MACH_PORT_VALID(kernel_task))
        {
            ret = nvpatch(kernel_task, kbase, "com.apple.System.boot-nonce");
        }
    }
    return ret;
}

bool set_generator(const char *gen)
{
    bool ret = false;

    CFStringRef str = CFStringCreateWithCStringNoCopy(NULL, gen, kCFStringEncodingUTF8, kCFAllocatorNull);
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if(!str || !dict)
    {
        LOG("Failed to allocate CF objects");
    }
    else
    {
        CFDictionarySetValue(dict, CFSTR("com.apple.System.boot-nonce"), str);
        CFRelease(str);

        io_service_t nvram = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
        if(!MACH_PORT_VALID(nvram))
        {
            LOG("Failed to get IODTNVRAM service");
        }
        else
        {
            if(party_hard() == 0)
            {
                kern_return_t kret = IORegistryEntrySetCFProperties(nvram, dict);
                LOG("IORegistryEntrySetCFProperties: %s", mach_error_string(kret));
                if(kret == KERN_SUCCESS)
                {
                    ret = true;
                }
            }
        }

        CFRelease(dict);
    }

    return ret;
}

bool dump_apticket(const char *to)
{
    bool ret = false;
    if(party_hard() == 0)
    {
        const char *from = "/System/Library/Caches/apticket.der";
        struct stat s;
        if(stat(from, &s) != 0)
        {
            LOG("stat failed: %s", strerror(errno));
        }
        else
        {
            FILE *in  = fopen(from, "rb");
            if(in == NULL)
            {
                LOG("failed to open src: %s", strerror(errno));
            }
            else
            {
                FILE *out = fopen(to, "wb");
                if(out == NULL)
                {
                    LOG("failed to open dst: %s", strerror(errno));
                }
                else
                {
                    char *buf = malloc(s.st_size);
                    if(buf == NULL)
                    {
                        LOG("failed to alloc buf: %s", strerror(errno));
                    }
                    else
                    {
                        fread(buf, s.st_size, 1, in);
                        fwrite(buf, s.st_size, 1, out);
                        free(buf);
                        ret = true;
                    }
                    fclose(out);
                }
                fclose(in);
            }
        }
    }
    return ret;
}
