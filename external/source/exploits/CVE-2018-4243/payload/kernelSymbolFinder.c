//
//  kernelSymbolFinder.c
//  KernelSymbolFinder
//
//  Created by Jake James on 8/21/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#include "kernelSymbolFinder.h"

#define SWAP32(p) __builtin_bswap32(p)

static FILE *file;
uint32_t offset = 0;

static void *load_bytes(FILE *obj_file, off_t offset, uint32_t size) {
    void *buf = calloc(1, size);
    fseek(obj_file, offset, SEEK_SET);
    fread(buf, size, 1, obj_file);
    return buf;
}

uint32_t find_macho_header() {
    uint32_t off = 0;
    uint32_t *magic = load_bytes(file, off, sizeof(uint32_t));
    while ((*magic & ~1) != 0xFEEDFACE) {
        off++;
        magic = load_bytes(file, off, sizeof(uint32_t));
    }
    return off - 1;
}

uint64_t find_symbol(const char *symbol, bool verbose) {
    
    //----This will store symbol address----//
    uint64_t addr = 0;
    
    //----This variable will hold the binary location as we move on through reading it----//
    size_t offset = 0;
    size_t sym_offset = 0;
    int ncmds = 0;
    struct load_command *cmd = NULL;
    uint32_t *magic = load_bytes(file, offset, sizeof(uint32_t)); //at offset 0 we have the magic number
    if (verbose) printf("[i] MAGIC = 0x%x\n", *magic);
    
    //----64bit magic number----//
    if (*magic == 0xFEEDFACF) {
        
        if (verbose) printf("[i] 64bit binary\n");
        
        struct mach_header_64 *mh64 = load_bytes(file, offset, sizeof(struct mach_header_64));
        ncmds = mh64->ncmds;
        free(mh64);
        
        offset += sizeof(struct mach_header_64);
        
        if (verbose) printf("[i] %d LOAD COMMANDS\n", ncmds);
        for (int i = 0; i < ncmds; i++) {
            cmd = load_bytes(file, offset, sizeof(struct load_command));
            if (verbose) printf("[i] LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
            
            if (cmd->cmd == LC_SYMTAB) {
                if (verbose) printf("[+] Found LC_SYMTAB command!\n");
                struct symtab_command *symtab = load_bytes(file, offset, cmd->cmdsize);
                if (verbose) printf("\t[i] %d symbols\n", symtab->nsyms);
                if (verbose) printf("\t[i] Symbol table at 0x%x\n", symtab->symoff);
                
                for (int i = 0; i < symtab->nsyms; i++) {
                    struct symbol *sym = load_bytes(file, symtab->symoff + sym_offset, sizeof(struct symbol));
                    
                    int symlen = 0;
                    int sym_str_addr = sym->table_index + symtab->stroff;
                    uint8_t *byte = load_bytes(file, sym_str_addr+symlen, 1);
                    
                    //strings end with 0 so that's how we know it's over
                    while (*byte != 0) {
                        free(byte);
                        symlen++;
                        byte = load_bytes(file, sym_str_addr+symlen, 1);
                    }
                    free(byte);
                    
                    char *sym_name = load_bytes(file, sym_str_addr, symlen + 1);
                    if (verbose) printf("\t%s: 0x%llx\n", sym_name, sym->address);
                    if (!strcmp(sym_name, symbol)) {
                        addr = sym->address;
                        if (!verbose) return addr;
                    }
                    free(sym_name);
                    sym_offset += sizeof(struct symbol);
                    free(sym);
                }
                
                free(symtab);
                free(cmd);
                break;
            }
            
            offset += cmd->cmdsize;
            free(cmd);
        }
    }
    //----32bit magic number----//
    else if (*magic == 0xFEEDFACE) {
        
        if (verbose) printf("[i] 32bit binary\n");
        
        struct mach_header *mh = load_bytes(file, offset, sizeof(struct mach_header));
        ncmds = mh->ncmds;
        free(mh);
        
        offset += sizeof(struct mach_header);
        
        if (verbose) printf("[i] %d LOAD COMMANDS\n", ncmds);
        for (int i = 0; i < ncmds; i++) {
            cmd = load_bytes(file, offset, sizeof(struct load_command));
            if (verbose) printf("[i] LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
            offset += cmd->cmdsize;
            
            if (cmd->cmd == LC_SYMTAB) {
                if (verbose) printf("[+] Found LC_SYMTAB command!\n");
                struct symtab_command *symtab = load_bytes(file, offset, cmd->cmdsize);
                if (verbose) printf("\t[i] %d symbols\n", symtab->nsyms);
                if (verbose) printf("\t[i] Symbol table at 0x%x\n", symtab->symoff);
                
                for (int i = 0; i < symtab->nsyms; i++) {
                    struct symbol *sym = load_bytes(file, symtab->symoff + sym_offset, sizeof(struct symbol));
                    
                    int symlen = 0;
                    int sym_str_addr = sym->table_index + symtab->stroff;
                    uint8_t *byte = load_bytes(file, sym_str_addr+symlen, 1);
                    
                    while (*byte != 0) {
                        free(byte);
                        symlen++;
                        byte = load_bytes(file, sym_str_addr+symlen, 1);
                    }
                    free(byte);
                    
                    char *sym_name = load_bytes(file, sym_str_addr, symlen + 1);
                    if (verbose) printf("\t%s: 0x%llx\n", sym_name, sym->address);
                    if (!strcmp(sym_name, symbol)) {
                        addr = sym->address;
                        if (!verbose) return addr;
                    }
                    free(sym_name);
                    sym_offset += sizeof(struct symbol);
                    free(sym);
                }
                
                free(symtab);
                free(cmd);
                break;
            }
            offset += cmd->cmdsize;
            free(cmd);
        }
    }
    else {
        if (verbose) printf("[!] Unrecognized file\n");
        return -1;
    }
    return addr;
}

int initWithKernelCache(const char *kernelcache) {
    file = fopen(kernelcache, "rb");
    offset = find_macho_header();
    if (!offset) {
        printf("[-] offset = 0; this isn't a macho, right?\n");
        return -1;
    }
    
    printf("[i] Mach-o header at 0x%X\n", offset);
    
    char * decompressed_kernel = "/var/mobile/.kernelcache.dec";
    unlink(decompressed_kernel);
    char strOff[128]; // I don't think a string of the offset can ever be bigger than 128 bytes
    sprintf(strOff, "0x%X", offset);
    char *args[5] = { strdup("lzssdec"), strdup("-o"), strdup(strOff), strdup(kernelcache), strdup(decompressed_kernel)};
    
    if (lzssdec(5, (char **)args)) {
        printf("[-] Failed decompression, this is lzss right?\n");
        return -1;
    }
    else printf("[+] Decompressed kernelcache!\n");
    fclose(file);
    file = fopen(decompressed_kernel, "rb");
    return 0;
}
