#include "lsym.h"
#import <Foundation/Foundation.h>

#include <IOKit/IOKitLib.h>

struct segment_command_64 *find_segment_64(struct mach_header_64 *mh, const char *segname);
struct section_64 *find_section_64(struct segment_command_64 *seg, const char *name);
struct load_command *find_load_command(struct mach_header_64 *mh, uint32_t cmd);
extern CFDictionaryRef OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);


extern CFDictionaryRef OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);
#ifdef FIND_KERNEL_SLIDE
static lsym_offset_t kaslr_slide=0;
static char kaslr_slide_found   =0;
#endif

__attribute__((always_inline))
lsym_kern_pointer_t kext_pointer(const char* identifier){
    return (lsym_kern_pointer_t)[((NSNumber*)(((__bridge NSDictionary*)OSKextCopyLoadedKextInfo(NULL, NULL))[[NSString stringWithUTF8String:identifier]][@"OSBundleLoadAddress"])) unsignedLongLongValue];
}

__attribute__((always_inline))
lsym_map_t *lsym_map_file(const char *path) {
    int fd=open(path, O_RDONLY);
if(fd < 0) return 0;
    struct stat sb;
    fstat(fd, &sb);
    if (sb.st_size < 0x1000) {
        return 0;
    }
    void* map = mmap(NULL, sb.st_size  & 0xFFFFFFFF, PROT_READ, MAP_SHARED, fd, 0);
    lsym_map_t* ret = (lsym_map_t*)malloc(sizeof(lsym_map_t));
    ret->map  = map;
    ret->path = path;
    ret->sz = sb.st_size & 0xFFFFFFFF;
    return ret;
}

__attribute__((always_inline))
lsym_kern_pointer_t lsym_find_gadget(lsym_map_t *mapping, const char *bytes, const uint32_t size, const lsym_gadget_flags flags) {
    lsym_offset_t off=(lsym_offset_t)memmem(mapping->map, mapping->sz, bytes, size);
    if (!off) {
        puts("[-] Couldn't find a ROP gadget, aborting.");
        exit(1);
    }
    return lsym_slide_pointer(((flags & LSYM_DO_NOT_REBASE) == 0 ? lsym_kernel_base(mapping) : 0)+(off - (lsym_offset_t) mapping->map));
}

__attribute__((always_inline))
lsym_kern_pointer_t lsym_kernel_base(lsym_map_t *mapping) {
    struct mach_header_64 *mh = mapping->map;
    struct segment_command_64 *text = find_segment_64(mh, SEG_TEXT);
    return (lsym_kern_pointer_t)text->vmaddr;
}
__attribute__((always_inline))
lsym_kern_pointer_t lsym_find_symbol(lsym_map_t *mapping, const char *name) {
    struct mach_header_64 *mh = mapping->map;
    struct symtab_command *symtab = NULL;
    struct segment_command_64 *linkedit = NULL;    
    /*
     * Check header
     */
    if (mh->magic != MH_MAGIC_64) {
        return (lsym_kern_pointer_t)NULL;
    }
    
    /*
     * Find the LINKEDIT and SYMTAB sections
     */
    linkedit = find_segment_64(mh, SEG_LINKEDIT);
    if (!linkedit) {
        return (lsym_kern_pointer_t)NULL;
    }
    
    symtab = (struct symtab_command *)find_load_command(mh, LC_SYMTAB);
    if (!symtab) {
        return (lsym_kern_pointer_t)NULL;
    }
    void* symtabp = symtab->stroff + 4 + (char*)mh;
    void* symtabz = symtab->stroff + (char*)mh;
    void* symendp = symtab->stroff + (char*)mh + symtab->strsize - 0xA;
    uint32_t idx = 0;
    while (symtabp < symendp) {
        if(strcmp(symtabp, name) == 0) goto found;
        symtabp += strlen((char*)symtabp) + 1;
        idx++;
    }
    printf("[-] symbol %s not resolved.\n", name); exit(0);
    return (lsym_kern_pointer_t)NULL;
found:;
    struct nlist_64* nlp = (struct nlist_64*) (((uint32_t)(symtab->symoff)) + (char*)mh);
    uint64_t strx = ((char*)symtabp - (char*)symtabz);
    unsigned int symp = 0;
    while(symp <= (symtab->nsyms)) {
        uint32_t strix = *((uint32_t*)nlp);
        if(strix == strx)
            goto found1;
        nlp ++; //sizeof(struct nlist_64);
        symp++;
    }
    printf("[-] symbol not found: %s\n", name);
    exit(-1);
found1:
    //printf("[+] found symbol %s at 0x%016llx\n", name, nlp->n_value);
    return (lsym_kern_pointer_t)nlp->n_value;

}

__attribute__((always_inline))
struct segment_command_64 *find_segment_64(struct mach_header_64 *mh, const char *segname)
{
    struct load_command *lc;
    struct segment_command_64 *s, *fs = NULL;
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT_64) {
            s = (struct segment_command_64 *)lc;
            if (!strcmp(s->segname, segname)) {
                fs = s;
                break;
            }
        }
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    return fs;
}

__attribute__((always_inline))
struct section_64 *find_section_64(struct segment_command_64 *seg, const char *name)
{
    struct section_64 *sect, *fs = NULL;
    uint32_t i = 0;
    for (i = 0, sect = (struct section_64 *)((uint64_t)seg + (uint64_t)sizeof(struct segment_command_64));
         i < seg->nsects;
         i++, sect = (struct section_64 *)((uint64_t)sect + sizeof(struct section_64)))
    {
        if (!strcmp(sect->sectname, name)) {
            fs = sect;
            break;
        }
    }
    return fs;
}

__attribute__((always_inline))
struct load_command *find_load_command(struct mach_header_64 *mh, uint32_t cmd)
{
    struct load_command *lc, *flc;
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == cmd) {
            flc = (struct load_command *)lc;
            break;
        }
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    return flc;
}
