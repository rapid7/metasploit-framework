require 'windows/api'

module Windows
  module Memory
    API.auto_namespace = 'Windows::Memory'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = false

    private

    GHND          = 0x0042
    GMEM_FIXED    = 0x0000
    GMEM_MOVABLE  = 0002
    GMEM_ZEROINIT = 0x0040
    GPTR          = 0x0040

    HEAP_NO_SERIALIZE          = 0x00000001
    HEAP_GENERATE_EXCEPTIONS   = 0x00000004
    HEAP_ZERO_MEMORY           = 0x00000008
    HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010
    HEAP_CREATE_ENABLE_EXECUTE = 0x00040000

    MEM_COMMIT      = 0x1000
    MEM_RESERVE     = 0x2000
    MEM_DECOMMIT    = 0x4000
    MEM_RELEASE     = 0x8000
    MEM_FREE        = 0x10000
    MEM_PRIVATE     = 0x20000
    MEM_MAPPED      = 0x40000
    MEM_RESET       = 0x80000
    MEM_TOP_DOWN    = 0x100000
    MEM_WRITE_WATCH = 0x200000
    MEM_PHYSICAL    = 0x400000
    MEM_LARGE_PAGES = 0x20000000
    MEM_4MB_PAGES   = 0x80000000200000

    PAGE_NOACCESS          = 0x01
    PAGE_READONLY          = 0x02
    PAGE_READWRITE         = 0x04
    PAGE_WRITECOPY         = 0x08
    PAGE_EXECUTE           = 0x10
    PAGE_EXECUTE_READ      = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_GUARD             = 0x100
    PAGE_NOCACHE           = 0x200
    PAGE_WRITECOMBINE      = 0x400

    SEC_FILE     = 0x800000
    SEC_IMAGE    = 0x1000000
    SEC_VLM      = 0x2000000
    SEC_RESERVE  = 0x4000000
    SEC_COMMIT   = 0x8000000
    SEC_NOCACHE  = 0x10000000

    LMEM_FIXED          = 0x0000
    LMEM_MOVEABLE       = 0x0002
    LMEM_NOCOMPACT      = 0x0010
    LMEM_NODISCARD      = 0x0020
    LMEM_ZEROINIT       = 0x0040
    LMEM_MODIFY         = 0x0080
    LMEM_DISCARDABLE    = 0x0F00
    LMEM_VALID_FLAGS    = 0x0F72
    LMEM_INVALID_HANDLE = 0x8000
    LMEM_DISCARDED      = 0x4000
    LMEM_LOCKCOUNT      = 0x00FF

    API.new('GlobalAlloc', 'LL', 'L')
    API.new('GlobalFlags', 'L', 'L')
    API.new('GlobalFree', 'L', 'L')
    API.new('GlobalHandle', 'P', 'L')
    API.new('GlobalLock', 'L', 'L')
    API.new('GlobalMemoryStatus', 'P', 'V')
    API.new('GlobalMemoryStatusEx', 'P', 'V')
    API.new('GlobalReAlloc', 'LLL', 'L')
    API.new('GlobalSize', 'L', 'L')
    API.new('GlobalUnlock', 'L', 'L')

    API.new('GetProcessHeap', 'V', 'L')
    API.new('GetProcessHeaps', 'LP', 'L')
    API.new('HeapAlloc', 'LLL', 'P')
    API.new('HeapCompact', 'LL', 'L')
    API.new('HeapCreate', 'LLL', 'L')
    API.new('HeapDestroy', 'L', 'B')
    API.new('HeapFree', 'LLL', 'B')
    API.new('HeapLock', 'L', 'B')
    API.new('HeapReAlloc', 'LLLL', 'L')
    API.new('HeapSize', 'LLL', 'L')
    API.new('HeapUnlock', 'L', 'B')
    API.new('HeapValidate', 'LLL', 'B')
    API.new('HeapWalk', 'LP', 'B')

    API.new('LocalAlloc', 'LL', 'L')
    API.new('LocalFlags', 'L', 'L')
    API.new('LocalFree', 'L', 'L')
    API.new('LocalHandle', 'L', 'L')
    API.new('LocalLock', 'L', 'L')
    API.new('LocalReAlloc', 'LLL', 'L')
    API.new('LocalSize', 'L', 'L')
    API.new('LocalUnlock', 'L', 'B')

    API.new('VirtualAlloc', 'LLLL', 'L')
    API.new('VirtualAllocEx', 'LLLLL', 'L')
    API.new('VirtualFree', 'LLL', 'B')
    API.new('VirtualFreeEx', 'LLLL', 'B')
    API.new('VirtualLock', 'LL', 'B')
    API.new('VirtualProtect', 'LLLP', 'B')
    API.new('VirtualProtectEx', 'LLLLP', 'B')
    API.new('VirtualQuery', 'LPL', 'L')
    API.new('VirtualQueryEx', 'LLPL', 'L')
    API.new('VirtualUnlock', 'LL', 'B')
    API.new('RtlZeroMemory', 'PL', 'L')

    # The LocalDiscard macro from winbase.h
    def LocalDiscard(mem_loc)
      LocalReAlloc(mem_loc, 0, LMEM_MOVEABLE)
    end

    # Windows XP or later
    begin
      API.new('HeapQueryInformation', 'LIPLL', 'B')
      API.new('HeapSetInformation', 'LIPL', 'B')
    rescue Win32::API::LoadLibraryError
      # Do nothing - you must check for their existence
    end
  end
end
