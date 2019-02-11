#import "utils.h"
#import "kernel_utils.h"

// simplified & commented version of https://github.com/JonathanSeals/kernelversionhacker
// this method relies on brute forcing the kaslr slide
// we know how big the slide can be and where the unslid kernel base is
// since we can't read from an unexisting address (smaller than the actual base) we start from the biggest possible slide and then go down
// the goal is to find what address points to the arm64 macho header: 0xfeedfacf
// for some reason 0xfeedfacf can be found multiple times so we need more checking than that
// for that we check for the presence of some strings right after it

uint64_t FindKernelBase() {
    printf("[*] Bruteforcing kaslr slide\n");
    
    #define slid_base  base+slide
    uint64_t base = 0xFFFFFFF007004000; // unslid kernel base on iOS 11
    uint32_t slide = 0x21000000; // maximum value the kaslr slide can have
    uint32_t data = KernelRead_32bits(slid_base); // the data our address points to
    
    for(;;) { /* keep running until we find the "__text" string
                     string must be less than 0x2000 bytes ahead of the kernel base
                     if it's not there the loop will go again */
        
        while (data != 0xFEEDFACF) { // find the macho header
            slide -= 0x200000;
            data = KernelRead_32bits(slid_base);
        }
        
        printf("[*] Found 0xfeedfacf header at 0x%llx, is that correct?\n", slid_base);
        
        char buf[0x120];
        for (uint64_t addr = slid_base; addr < slid_base + 0x2000; addr += 8 /* 64 bits / 8 bits / byte = 8 bytes */) {
            KernelRead(addr, buf, 0x120); // read 0x120 bytes into a char buffer
            
            if (!strcmp(buf, "__text") && !strcmp(buf + 16, "__PRELINK_TEXT")) { // found it!
                printf("\t[+] Yes! Found __text and __PRELINK_TEXT!\n");
                printf("\t[i] kernel base at 0x%llx\n", slid_base);
                printf("\t[i] kaslr slide is 0x%x\n", slide);
                printf("\t[i] kernel header is 0x%x\n", KernelRead_32bits(slid_base));
                return slid_base;
            }
            data = 0;
        }
        printf("\t[-] Nope. Can't find __text and __PRELINK_TEXT, trying again!\n");
    }
    return 0;
}

uint64_t binary_load_address(mach_port_t tp) {
    kern_return_t err;
    mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object_name = MACH_PORT_NULL; /* unused */
    mach_vm_size_t target_first_size = 0x1000;
    mach_vm_address_t target_first_addr = 0x0;
    struct vm_region_basic_info_64 region = {0};
    printf("[+] About to call mach_vm_region\n");
    err = mach_vm_region(tp,
                         &target_first_addr,
                         &target_first_size,
                         VM_REGION_BASIC_INFO_64,
                         (vm_region_info_t)&region,
                         &region_count,
                         &object_name);
    
    if (err != KERN_SUCCESS) {
        printf("[-] Failed to get the region: %s\n", mach_error_string(err));
        return -1;
    }
    printf("[+] Got base address\n");
    
    return target_first_addr;
}

