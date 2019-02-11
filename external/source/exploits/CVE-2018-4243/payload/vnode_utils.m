//
//  *.c
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import "kernel_utils.h"
#import "patchfinder64.h"
#import "offsetof.h"
#import "offsets.h"
#import "kexecute.h"
#import "kernelSymbolFinder.h"
#import <stdlib.h>

extern uint64_t KASLR_Slide;

int vnode_lookup(const char *path, int flags, uint64_t *vnode, uint64_t vfs_context) {
    
    size_t len = strlen(path) + 1;
    uint64_t ptr = Kernel_alloc(8);
    uint64_t ptr2 = Kernel_alloc(len);
    KernelWrite(ptr2, path, len);
    
    if (Kernel_Execute(find_symbol("_vnode_lookup", false) + KASLR_Slide, ptr2, flags, ptr, vfs_context, 0, 0, 0)) {
        return -1;
    }
    *vnode = KernelRead_64bits(ptr);
    Kernel_free(ptr2, len);
    Kernel_free(ptr, 8);
    return 0;
}

uint64_t get_vfs_context() {
    return ZmFixAddr(Kernel_Execute(find_symbol("_vfs_context_current", false) + KASLR_Slide, 1, 0, 0, 0, 0, 0, 0));
}

int vnode_put(uint64_t vnode) {
    return (int)Kernel_Execute(find_symbol("_vnode_put", false) + KASLR_Slide, vnode, 0, 0, 0, 0, 0, 0);
}
