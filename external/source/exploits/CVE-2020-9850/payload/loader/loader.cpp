#include <mach-o/loader.h>
#include <stdio.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define printf(...)
#define setvbuf(...)

extern void *(*dlopen_ptr)(const char *path, int mode);
extern void *(*dlsym_ptr)(void *handle, const char *symbol);

__asm__(".include \"" CURRENT_DIR "/entry.s\"");

inline void exit(int n) {
    printf("%d\n", n);
}

inline void memcpy(void *dst, void *src, size_t n) {
    char *dst_ = (char *)dst, *src_ = (char *)src;
    while(n--)
        *dst_++ = *src_++;
}

inline int memcmp(void *dst, void *src, size_t n) {
    char *dst_ = (char *)dst, *src_ = (char *)src;
    while(n--) if(*dst_++ != *src_++) return 1;
    return 0;
}

inline uint64_t read_uleb128(uint8_t*& p, uint8_t* end)
{
    uint64_t result = 0;
    int         bit = 0;
    do {
        if ( p == end ) {
            exit(1);
            break;
        }
        uint64_t slice = *p & 0x7f;

        if ( bit > 63 ) {
            exit(2);
            break;
        }
        else {
            result |= (slice << bit);
            bit += 7;
        }
    }
    while (*p++ & 0x80);
    return result;
}

inline void vm_(uint64_t base, void **libs, load_command **commands, void *mem, uint8_t *cmd, size_t size) {
    uint8_t *p = cmd, *end = cmd + size;
    int ordinal = 0, libIndex = 0;
    const char *symbolName;
    bool done = false;
    uint8_t segIndex;
    uintptr_t segOffset;
    off_t offset;
    int type;
    // ported from dyld
    while ( !done && (p < end) ) {
        uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
        uint8_t opcode = *p & BIND_OPCODE_MASK;
        ++p;
        switch (opcode) {
            case BIND_OPCODE_DONE:
                break;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                libIndex = immediate;
                break;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                libIndex = (int)read_uleb128(p, end);
                break;
            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                // the special ordinals are negative numbers
                if ( immediate == 0 )
                    ordinal = 0;
                else {
                    int8_t signExtended = BIND_OPCODE_MASK | immediate;
                    ordinal = signExtended;
                }
                break;
            case BIND_OPCODE_ADD_ADDR_ULEB:
                segOffset += read_uleb128(p, end);
                break;
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbolName = (char*)p;
                while (*p != '\0')
                    ++p;
                ++p;
                break;
            case BIND_OPCODE_SET_TYPE_IMM:
                type = immediate;
                break;
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segIndex  = immediate;
                segOffset = read_uleb128(p, end);
                break;
            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = read_uleb128(p, end);
                uint64_t skip = read_uleb128(p, end);
                segOffset += count * (skip + sizeof(intptr_t));
                break;
            }
            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            case BIND_OPCODE_DO_BIND: {
                void *res = dlsym_ptr(libs[libIndex], symbolName + 1);
                offset = ((segment_command_64 *)commands[segIndex])->vmaddr + segOffset - base;
                printf("%llx (+%lx) %s %d\n", offset, segOffset, symbolName, type);
                printf("dlsym(libs[%d] == %p, \"%s\") == %p\n", libIndex, libs[libIndex], symbolName + 1, res);
                if(symbolName[0] == '_')
                    *(void **)((char *)mem + offset) = res;
                // if not, it's from dyld I guess
                segOffset += 8;
                if(opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED)
                    segOffset += immediate * 8;
                break;
            }
            default:
                printf("WARNING: unsupported command: 0x%x\n", opcode);
                // exit(-1);
        }
    }
}

inline void rebase_vm_(uint64_t base, void **libs, load_command **commands, void *map, uint8_t *cmd, size_t size) {
    uint8_t *p = cmd, *end = cmd + size;
    uint8_t  type = 0;
    int      segIndex = 0;
    uint64_t segOffset = 0;
    uint64_t count;
    uint64_t skip;
    bool     segIndexSet = false;
    bool     stop = false;
    int ptrSize = 8;
    while ( !stop && (p < end) ) {
        uint8_t immediate = *p & REBASE_IMMEDIATE_MASK;
        uint8_t opcode = *p & REBASE_OPCODE_MASK;
        ++p;
        switch (opcode) {
            case REBASE_OPCODE_DONE:
                if ( (end - p) > 8 )
                    exit(100);
                stop = true;
                break;
            case REBASE_OPCODE_SET_TYPE_IMM:
                type = immediate;
                break;
            case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segIndex = immediate;
                segOffset = read_uleb128(p, end);
                segIndexSet = true;
                break;
            case REBASE_OPCODE_ADD_ADDR_ULEB:
                segOffset += read_uleb128(p, end);
                break;
            case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                segOffset += immediate*ptrSize;
                break;
            case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
                if(opcode == REBASE_OPCODE_DO_REBASE_IMM_TIMES)
                    count = immediate;
                else
                    count = read_uleb128(p, end);
                for (uint32_t i=0; i < count; ++i) {
                    uintptr_t offset = ((segment_command_64 *)commands[segIndex])->vmaddr + segOffset - base;
                    printf("rebase %lx (+%llx)\n", offset, segOffset);
                    *(uintptr_t *)((uintptr_t)map + offset) += ((uintptr_t)map - base);
                    segOffset += ptrSize;
                }
                break;
            case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
                uintptr_t offset = ((segment_command_64 *)commands[segIndex])->vmaddr + segOffset - base;
                printf("rebase %lx (+%llx)\n", offset, segOffset);
                *(uintptr_t *)((uintptr_t)map + offset) += ((uintptr_t)map - base);
                segOffset += read_uleb128(p, end) + ptrSize;
                break;
            }
            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
                count = read_uleb128(p, end);
                skip = read_uleb128(p, end);
                for (uint32_t i=0; i < count; ++i) {
                    uintptr_t offset = ((segment_command_64 *)commands[segIndex])->vmaddr + segOffset - base;
                    printf("rebase %lx (+%llx)\n", offset, segOffset);
                    *(uintptr_t *)((uintptr_t)map + offset) += ((uintptr_t)map - base);
                    segOffset += skip + ptrSize;
                    if ( stop )
                        break;
                }
                break;
            default:
                exit(101);
        }
    }
}

#define vm(offset, size) vm_(base, libs, commands, map, (uint8_t *)mem + offset, size)
#define rebase_vm(offset, size) rebase_vm_(base, libs, commands, map, (uint8_t *)mem + offset, size)

extern "C" void load(void *mem, void *args) {
    setvbuf(stdout, 0, _IONBF, 0);
    mach_header *header = (mach_header *)mem;
    load_command* startCmds = (load_command*)((char *)header + sizeof(mach_header_64));
    load_command *cmd;

    printf("%x %x\n", header->magic, MH_MAGIC_64);
    size_t highest_address = 0;

    load_command *commands[0x80];
    void *libs[0x80 + 1];
    int libCount = 1;
    uint64_t base = 0;
    char pagezero[] = "__PAGEZERO";

#define LC cmd = startCmds; for (uint32_t i = 0; i < header->ncmds; ++i, cmd = (load_command*)((char *)cmd + cmd->cmdsize))

    LC {
        if(cmd->cmd != LC_SEGMENT_64) continue;
        auto seg = (segment_command_64 *)cmd;
        size_t end = seg->vmaddr + seg->vmsize;

        if(!memcmp(seg->segname, (void *)pagezero, 11))
            base = seg->vmsize;

        if(highest_address < end) {
            highest_address = end;
        }

        commands[i] = cmd;
    }

    highest_address -= base;
    commands[header->ncmds] = 0;

    printf("%lx\n", highest_address);
    void *map = mmap(NULL, highest_address, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_PRIVATE|MAP_JIT, -1, 0);

    uint64_t entry = 0;
    dysymtab_command *symtab;

    LC {
        if(cmd->cmd == LC_SEGMENT_64) {
            auto seg = (segment_command_64 *)cmd;
            memcpy((char *)map + seg->vmaddr - base, (char *)mem + seg->fileoff, seg->filesize);
        }

        if(cmd->cmd == 0x80000028) {
            auto entrycmd = (entry_point_command *)cmd;
            entry = entrycmd->entryoff;
        }

        if(cmd->cmd == LC_SYMTAB) {
            symtab = (dysymtab_command *)cmd;
        }

        if(cmd->cmd == LC_LOAD_DYLIB) {
            auto dylib = (dylib_command *)cmd;
            libs[libCount++] = dlopen_ptr((const char *)dylib + dylib->dylib.name.offset, RTLD_LAZY);
        }
    }

    LC {
        printf("cmd: %x\n", cmd->cmd);

        if(cmd->cmd == LC_DYLD_INFO_ONLY) {
            auto dyld = (dyld_info_command *)cmd;

            rebase_vm(dyld->rebase_off, dyld->rebase_size);
            vm(dyld->bind_off, dyld->bind_size);
            vm(dyld->lazy_bind_off, dyld->lazy_bind_size);
        }
    }

    if(!entry) {
        for(size_t i = 0; i < highest_address; i++) {
            int *cur = (int *)((char *)map + i);
            if(cur[0] == 0x13371337) {
                entry = i + 16;
                printf("%lx %llx\n", i, entry);
                break;
            }
        }
    }

    entry += (uint64_t)map;
    printf("%p\n", (void *)entry);
    ((void (*)(int, void *))(entry))(1, args);
}
