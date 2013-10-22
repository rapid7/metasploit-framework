#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# Map a PE file under another OS using DynLdr, API imports are redirected to ruby callback for emulation
#

require 'metasm'

class PeLdr
  attr_accessor :pe, :load_address
  DL = Metasm::DynLdr

  # load a PE file, setup basic IAT hooks (raises "unhandled lib!import")
  def initialize(file, hooktype=:iat)
    if file.kind_of? Metasm::PE
      @pe = file
    elsif file[0, 2] == 'MZ' and file.length > 0x3c
      @pe = Metasm::PE.decode(file)
    else	# filename
      @pe = Metasm::PE.decode_file(file)
    end
    @load_address = DL.memory_alloc(@pe.optheader.image_size)
    raise 'malloc' if @load_address == 0xffff_ffff
    
    puts "map sections" if $DEBUG
    DL.memory_write(@load_address, @pe.encoded.data[0, @pe.optheader.headers_size].to_str)
    @pe.sections.each { |s|
      DL.memory_write(@load_address+s.virtaddr, s.encoded.data.to_str)
    }
    
    puts "fixup sections" if $DEBUG
    off = @load_address - @pe.optheader.image_base
    @pe.relocations.to_a.each { |rt|
      base = rt.base_addr
      rt.relocs.each { |r|
        if r.type == 'HIGHLOW'
          ptr = @load_address + base + r.offset
          old = DL.memory_read(ptr, 4).unpack('V').first
          DL.memory_write_int(ptr, old + off)
        end
      }
    }

    @iat_cb = {}
    @eat_cb = {}
    case hooktype
    when :iat
      puts "hook IAT" if $DEBUG
      @pe.imports.to_a.each { |id|
        ptr = @load_address + id.iat_p
        id.imports.each { |i|
          n = "#{id.libname}!#{i.name}"
          cb = DL.callback_alloc_c('void x(void)') { raise "unemulated import #{n}" }
          DL.memory_write_int(ptr, cb)
          @iat_cb[n] = cb
          ptr += 4
        }
      }
    when :eat, :exports
      puts "hook EAT" if $DEBUG
      ptr = @load_address + @pe.export.func_p
      @pe.export.exports.each { |e|
        n = e.name || e.ordinal
        cb = DL.callback_alloc_c('void x(void)') { raise "unemulated export #{n}" }
        DL.memory_write_int(ptr, cb - @load_address)	# RVA
        @eat_cb[n] = cb
        ptr += 4
      }
    end
  end

  # reset original expected memory protections for the sections
  # the IAT may reside in a readonly section, so call this only after all hook_imports
  def reprotect_sections
    @pe.sections.each { |s|
      p = ''
      p << 'r' if s.characteristics.include? 'MEM_READ'
      p << 'w' if s.characteristics.include? 'MEM_WRITE'
      p << 'x' if s.characteristics.include? 'MEM_EXECUTE'
      DL.memory_perm(@load_address + s.virtaddr, s.virtsize, p)
    }
  end

  # add a specific hook for an IAT function
  # accepts a function pointer in proto
  # exemple: hook_import('KERNEL32.dll', 'GetProcAddress', '__stdcall int f(int, char*)') { |h, name| puts "getprocaddr #{name}" ; 0 }
  def hook_import(libname, impname, proto, &b)
    @pe.imports.to_a.each { |id|
      next if id.libname != libname
      ptr = @load_address + id.iat_p
      id.imports.each { |i|
        if i.name == impname
          DL.callback_free(@iat_cb["#{libname}!#{impname}"])
          if proto.kind_of? Integer
            cb = proto
          else
            cb = DL.callback_alloc_c(proto, &b)
            @iat_cb["#{libname}!#{impname}"] = cb
          end
          DL.memory_write_int(ptr, cb)
        end
        ptr += 4
      }
    }
  end

  # add a specific hook in the export table
  # exemple: hook_export('ExportedFunc', '__stdcall int f(int, char*)') { |i, p| blabla ; 1 }
  def hook_export(name, proto, &b)
    ptr = @load_address + @pe.export.func_p
    @pe.export.exports.each { |e|
      n = e.name || e.ordinal
      if n == name
        DL.callback_free(@eat_cb[name])
        if proto.kind_of? Integer
          cb = proto
        else
          cb = DL.callback_alloc_c(proto, &b)
          @eat_cb[name] = cb
        end
        DL.memory_write_int(ptr, cb - @load_address)	# RVA
      end
      ptr += 4
    }
  end

  # run the loaded PE entrypoint
  def run_init
    ptr = @pe.optheader.entrypoint
    if ptr != 0
      ptr += @load_address
      DL.raw_invoke(ptr, [@load_address, 1, 1], 1)
    end
  end

  # similar to DL.new_api_c for the mapped PE
  def new_api_c(proto)
    proto += ';'    # allow 'int foo()'
    cp = DL.host_cpu.new_cparser
    cp.parse(proto)
    cp.toplevel.symbol.each_value { |v|
      next if not v.kind_of? Metasm::C::Variable      # enums
      if e = pe.export.exports.find { |e_| e_.name == v.name and e_.target }
        DL.new_caller_for(cp, v, v.name.downcase, @load_address + pe.label_rva(e.target))
      end
    }

    cp.numeric_constants.each { |k, v|
      n = k.upcase
      n = "C#{n}" if n !~ /^[A-Z]/
      DL.const_set(n, v) if not DL.const_defined?(n) and v.kind_of? Integer
    }
  end

  # maps a TEB/PEB in the current process, sets the fs register to point to it
  def self.setup_teb
    @@teb = DL.memory_alloc(4096)
    @@peb = DL.memory_alloc(4096)
    populate_teb
    populate_peb
    fs = allocate_ldt_entry_teb
    DL.new_func_c('__fastcall void set_fs(int i) { asm("mov fs, ecx"); }') { DL.set_fs(fs) }
  end

  # fills a fake TEB structure
  def self.populate_teb
    DL.memory_write(@@teb, 0.chr*4096)
    set = lambda { |off, val| DL.memory_write_int(@@teb+off, val) }
    # the stack will probably never go higher than that whenever in the dll...
    set[0x4, DL.new_func_c('int get_sp(void) { asm("mov eax, esp  and eax, ~0xfff"); }') { DL.get_sp }]	# stack_base
    set[0x8, 0x10000]	# stack_limit
    set[0x18, @@teb]	# teb
    set[0x30, @@peb]	# peb
  end

  def self.populate_peb
    DL.memory_write(@@peb, 0.chr*4096)
    set = lambda { |off, val| DL.memory_write_int(@@peb+off, val) }
  end

  def self.teb ; @@teb ; end
  def self.peb ; @@peb ; end

  # allocate an LDT entry for the teb, returns a value suitable for the fs selector
  def self.allocate_ldt_entry_teb
    entry = 1
    # ldt_entry base_addr size_in_pages
    # 32bits:1 type:2 (0=data) readonly:1 limit_in_pages:1 seg_not_present:1 usable:1
    struct = [entry, @@teb, 1, 0b1_0_1_0_00_1].pack('VVVV')
    Kernel.syscall(123, 1, DL.str_ptr(struct), struct.length)	# __NR_modify_ldt
    (entry << 3) | 7
  end

  setup_teb
end

# generate a fake PE which exports stuff found in k32/ntdll
# so that other lib may directly scan this PE with their own getprocaddr
class FakeWinAPI < PeLdr
  attr_accessor :win_version
  attr_accessor :exports

  def initialize(elist=nil)
    @exports = []
    @win_version = { :major => 5, :minor => 1, :build => 2600, :sp => 'Service pack 3', :sp_major => 3, :sp_minor => 0 }

    # if you know the exact list you need, put it there (much faster)
    if not elist
      elist = Metasm::WindowsExports::EXPORT.map { |k, v| k if v =~ /kernel32|ntdll/i }.compact
      elist |= ['free', 'malloc', 'memset', '??2@YAPAXI@Z', '_initterm', '_lock', '_unlock', '_wcslwr', '_wcsdup', '__dllonexit']
    end

    src = ".libname 'emu_winapi'\ndummy: int 3\n" + elist.map { |e| ".export #{e.inspect} dummy" }.join("\n")
    super(Metasm::PE.assemble(Metasm::Ia32.new, src).encode_string(:lib), :eat)	# put 'nil' instead of :eat if all exports are emu

    @heap = {}
    malloc = lambda { |sz| str = 0.chr*sz ; ptr = DL.str_ptr(str) ; @heap[ptr] = str ; ptr }

    lasterr = 0

    # kernel32
    hook_export('CloseHandle', '__stdcall int f(int)') { |a| 1 }
    hook_export('DuplicateHandle', '__stdcall int f(int, int, int, void*, int, int, int)') { |*a| DL.memory_write_int(a[3], a[1]) ; 1 }
    hook_export('EnterCriticalSection', '__stdcall int f(void*)') { 1 }
    hook_export('GetCurrentProcess', '__stdcall int f(void)') { -1 }
    hook_export('GetCurrentProcessId', '__stdcall int f(void)') { Process.pid }
    hook_export('GetCurrentThreadId', '__stdcall int f(void)') { Process.pid }
    hook_export('GetEnvironmentVariableW', '__stdcall int f(void*, void*, int)') { |name, resp, sz|
      next 0 if name == 0
      s = DL.memory_read_wstrz(name)
      s = s.unpack('v*').pack('C*') rescue nil
puts "GetEnv #{s.inspect}" if $VERBOSE
      v = ENV[s].to_s
      if resp and v.length*2+2 <= sz
        DL.memory_write(resp, (v.unpack('C*') << 0).pack('v*'))
        v.length*2	# 0 if not found
      else
        v.length*2+2
      end
    }
    hook_export('GetLastError', '__stdcall int f(void)') { lasterr }
    hook_export('GetProcAddress', '__stdcall int f(int, char*)') { |h, v|
      v = DL.memory_read_strz(v) if v >= 0x10000
puts "GetProcAddr #{'0x%x' % h}, #{v.inspect}" if $VERBOSE
      @eat_cb[v] or raise "unemulated getprocaddr #{v}"
    }
    hook_export('GetSystemInfo', '__stdcall void f(void*)') { |ptr|
      DL.memory_write(ptr, [0, 0x1000, 0x10000, 0x7ffeffff, 1, 1, 586, 0x10000, 0].pack('V*'))
      1
    }
    hook_export('GetSystemTimeAsFileTime', '__stdcall void f(void*)') { |ptr|
      v = ((Time.now - Time.mktime(1971, 1, 1, 0, 0, 0) + 370*365.25*24*60*60) * 1000 * 1000 * 10).to_i
      DL.memory_write(ptr, [v & 0xffffffff, (v >> 32 & 0xffffffff)].pack('VV'))
      1
    }
    hook_export('GetTickCount', '__stdcall int f(void)') { (Time.now.to_i * 1000) & 0xffff_ffff }
    hook_export('GetVersion', '__stdcall int f(void)') { (@win_version[:build] << 16) | (@win_version[:major] << 8) | @win_version[:minor]  }
    hook_export('GetVersionExA', '__stdcall int f(void*)') { |ptr|
      sz = DL.memory_read(ptr, 4).unpack('V').first
      data = [@win_version[:major], @win_version[:minor], @win_version[:build], 2, @win_version[:sp], @win_version[:sp_major], @win_version[:sp_minor]].pack('VVVVa128VV')
      DL.memory_write(ptr+4, data[0, sz-4])
      1
    }
    hook_export('HeapAlloc', '__stdcall int f(int, int, int)') { |h, f, sz| malloc[sz] }
    hook_export('HeapCreate', '__stdcall int f(int, int, int)') { 1 }
    hook_export('HeapFree', '__stdcall int f(int, int, int)') { |h, f, p| @heap.delete p ; 1 }
    hook_export('InterlockedCompareExchange', '__stdcall int f(int*, int, int)'+
      '{ asm("mov eax, [ebp+16]  mov ecx, [ebp+12]  mov edx, [ebp+8]  lock cmpxchg [edx], ecx"); }')
    hook_export('InterlockedExchange', '__stdcall int f(int*, int)'+
      '{ asm("mov eax, [ebp+12]  mov ecx, [ebp+8]  lock xchg [ecx], eax"); }')
    hook_export('InitializeCriticalSectionAndSpinCount', '__stdcall int f(int, int)') { 1 }
    hook_export('InitializeCriticalSection', '__stdcall int f(void*)') { 1 }
    hook_export('LeaveCriticalSection', '__stdcall int f(void*)') { 1 }
    hook_export('QueryPerformanceCounter', '__stdcall int f(void*)') { |ptr|
      v = (Time.now.to_f * 1000 * 1000).to_i
      DL.memory_write(ptr, [v & 0xffffffff, (v >> 32 & 0xffffffff)].pack('VV'))
      1
    }
    hook_export('SetLastError', '__stdcall int f(int)') { |i| lasterr = i ; 1 }
    hook_export('TlsAlloc', '__stdcall int f(void)') { 1 }

    # ntdll
    readustring = lambda { |p| DL.memory_read(*DL.memory_read(p, 8).unpack('vvV').values_at(2, 0)) }
    hook_export('RtlEqualUnicodeString', '__stdcall int f(void*, void*, int)') { |s1, s2, cs|
      s1 = readustring[s1]
      s2 = readustring[s2]
puts "RtlEqualUnicodeString #{s1.unpack('v*').pack('C*').inspect}, #{s2.unpack('v*').pack('C*').inspect}, #{cs}" if $VERBOSE
      if cs == 1
        s1 = s1.downcase
        s2 = s2.downcase
      end
      s1 == s2 ? 1 : 0
    }
    hook_export('MultiByteToWideChar', '__stdcall int f(int, int, void*, int, void*, int)') { |cp, fl, ip, is, op, os|
      is = DL.memory_read_strz(ip).length if is == 0xffff_ffff
      if os == 0
        is
      elsif os >= is*2	# not sure with this..
        DL.memory_write(op, DL.memory_read(ip, is).unpack('C*').pack('v*'))
        is
      else 0
      end

    }
    hook_export('LdrUnloadDll', '__stdcall int f(int)') { 0 }

    # msvcrt
    hook_export('free', 'void f(int)') { |i| @heap.delete i ; 0}
    hook_export('malloc', 'int f(int)') { |i| malloc[i] }
    hook_export('memset', 'char* f(char* p, char c, int n) { while (n--) p[n] = c; return p; }')
    hook_export('??2@YAPAXI@Z', 'int f(int)') { |i| raise 'fuuu' if i > 0x100000 ; malloc[i] } # at some point we're called with a ptr as arg, may be a peldr bug
    hook_export('__dllonexit', 'int f(int, int, int)') { |i, ii, iii| i }
    hook_export('_initterm', 'void f(void (**p)(void), void*p2) { while(p < p2) { if (*p) (**p)(); p++; } }')
    hook_export('_lock', 'void f(int)') { 0 }
    hook_export('_unlock', 'void f(int)') { 0 }
    hook_export('_wcslwr', '__int16* f(__int16* p) { int i=-1; while (p[++i]) p[i] |= 0x20; return p; }')
    hook_export('_wcsdup', 'int f(__int16* p)') { |p|
      cp = DL.memory_read_wstrz(p) + "\0\0"
      p = DL.str_ptr(cp)
      @heap[p] = cp
      p
    }
  end

  def hook_export(*a, &b)
    @exports |= [a.first]
    super(*a, &b)
  end

  # take another PeLdr and patch its IAT with functions from our @exports (eg our explicit export hooks)
  def intercept_iat(ldr)
    ldr.pe.imports.to_a.each { |id|
      id.imports.each { |i|
        next if not @exports.include? i.name or not @eat_cb[i.name]
        ldr.hook_import(id.libname, i.name, @eat_cb[i.name])
      }
    }
  end
end

if $0 == __FILE__
  dl = Metasm::DynLdr

  l = PeLdr.new('dbghelp.dll')
  #dl.memory_write(l.load_address + 0x33b10, "\x90\xcc")	# break on SymInitializeW

  puts 'dbghelp@%x' % l.load_address if $VERBOSE

  wapi = FakeWinAPI.new %w[CloseHandle DuplicateHandle EnterCriticalSection GetCurrentProcess GetCurrentProcessId GetCurrentThreadId GetEnvironmentVariableW GetLastError GetProcAddress GetSystemInfo GetSystemTimeAsFileTime GetTickCount GetVersion GetVersionExA HeapAlloc HeapCreate HeapFree InterlockedCompareExchange InterlockedExchange InitializeCriticalSectionAndSpinCount InitializeCriticalSection LeaveCriticalSection QueryPerformanceCounter SetLastError TlsAlloc RtlEqualUnicodeString MultiByteToWideChar free malloc memset ??2@YAPAXI@Z __dllonexit _initterm _lock _unlock _wcslwr _wcsdup GetModuleHandleA LoadLibraryA NtQueryObject NtQueryInformationProcess LdrUnloadDll]
  puts 'wapi@%x' % wapi.load_address if $VERBOSE
  
  wapi.hook_export('GetModuleHandleA', '__stdcall int f(char*)') { |ptr|
    s = dl.memory_read_strz(ptr) if ptr
    case s
    when /kernel32|ntdll/i; wapi.load_address
    else 0
    end
  }
  wapi.hook_export('LoadLibraryA', '__stdcall int f(char*)') { |ptr|
    s = dl.memory_read_strz(ptr)
    case s
    when /kernel32|ntdll/i; wapi.load_address
    else puts "LoadLibrary #{s.inspect}" ; 0
    end
  }
  wapi.hook_export('NtQueryObject', '__stdcall int f(int, int, void*, int, int*)') { |h, type, resp, sz, psz|
puts "NtQueryObject #{h}, #{type}, #{sz}" if $VERBOSE
    if h == 42 and type == 2 and sz >= 24
      dl.memory_write(resp, [14, 16, resp+8].pack('vvV') + "Process\0".unpack('C*').pack('v*'))
      dl.memory_write_int(psz, 24) if psz
      0
    else
      0x8000_0000
    end
  }
  wapi.hook_export('NtQueryInformationProcess', '__stdcall int f(int, int, void*, int, int*)') { |h, type, resp, sz, psz|
puts "NtQueryInformationProcess #{h}, #{type}, #{sz}" if $VERBOSE
    if h == 42 and type == 0
      # reservd peb res res ptr_to_pid
      peb = 0xdead0000
      dl.memory_write(resp, [42, peb, 0, 0, resp, 0].pack('V*'))
      dl.memory_write_int(psz, 24) if psz
      0
    else
      0x8000_0000
    end
  }
#puts wapi.exports.join(' ')	# generate arglist for FakeWinAPI.new
# TODO hook the resolv function of dbghelp to list what it checks

  wapi.intercept_iat(l)


  l.reprotect_sections

  l.new_api_c <<EOS
#define SYMOPT_CASE_INSENSITIVE         0x00000001
#define SYMOPT_UNDNAME                  0x00000002
#define SYMOPT_DEFERRED_LOADS           0x00000004
#define SYMOPT_NO_CPP                   0x00000008
#define SYMOPT_LOAD_LINES               0x00000010
#define SYMOPT_OMAP_FIND_NEAREST        0x00000020
#define SYMOPT_LOAD_ANYTHING            0x00000040
#define SYMOPT_IGNORE_CVREC             0x00000080
#define SYMOPT_NO_UNQUALIFIED_LOADS     0x00000100
#define SYMOPT_FAIL_CRITICAL_ERRORS     0x00000200
#define SYMOPT_EXACT_SYMBOLS            0x00000400
#define SYMOPT_ALLOW_ABSOLUTE_SYMBOLS   0x00000800
#define SYMOPT_IGNORE_NT_SYMPATH        0x00001000
#define SYMOPT_INCLUDE_32BIT_MODULES    0x00002000
#define SYMOPT_PUBLICS_ONLY             0x00004000
#define SYMOPT_NO_PUBLICS               0x00008000
#define SYMOPT_AUTO_PUBLICS             0x00010000
#define SYMOPT_NO_IMAGE_SEARCH          0x00020000
#define SYMOPT_SECURE                   0x00040000
#define SYMOPT_NO_PROMPTS               0x00080000
#define SYMOPT_DEBUG                    0x80000000

typedef int BOOL;
typedef char CHAR;
typedef unsigned long DWORD;
typedef unsigned __int64 DWORD64;
typedef void *HANDLE;
typedef unsigned __int64 *PDWORD64;
typedef void *PVOID;
typedef unsigned long ULONG;
typedef unsigned __int64 ULONG64;
typedef const CHAR *PCSTR;
typedef CHAR *PSTR;

struct _SYMBOL_INFO {
        ULONG SizeOfStruct;
        ULONG TypeIndex;
        ULONG64 Reserved[2];
        ULONG info;
        ULONG Size;
        ULONG64 ModBase;
        ULONG Flags;
        ULONG64 Value;
        ULONG64 Address;
        ULONG Register;
        ULONG Scope;
        ULONG Tag;
        ULONG NameLen;
        ULONG MaxNameLen;
        CHAR Name[1];
};
typedef struct _SYMBOL_INFO *PSYMBOL_INFO;

typedef __stdcall BOOL (*PSYM_ENUMERATESYMBOLS_CALLBACK)(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext);
__stdcall DWORD SymGetOptions(void);
__stdcall DWORD SymSetOptions(DWORD SymOptions __attribute__((in)));
__stdcall BOOL SymInitialize(HANDLE hProcess __attribute__((in)), PSTR UserSearchPath __attribute__((in)), BOOL fInvadeProcess __attribute__((in)));
__stdcall DWORD64 SymLoadModule64(HANDLE hProcess __attribute__((in)), HANDLE hFile __attribute__((in)), PSTR ImageName __attribute__((in)), PSTR ModuleName __attribute__((in)), DWORD64 BaseOfDll __attribute__((in)), DWORD SizeOfDll __attribute__((in)));
__stdcall BOOL SymSetSearchPath(HANDLE hProcess __attribute__((in)), PSTR SearchPathA __attribute__((in)));
__stdcall BOOL SymFromAddr(HANDLE hProcess __attribute__((in)), DWORD64 Address __attribute__((in)), PDWORD64 Displacement __attribute__((out)), PSYMBOL_INFO Symbol __attribute__((in)) __attribute__((out)));
__stdcall BOOL SymEnumSymbols(HANDLE hProcess __attribute__((in)), ULONG64 BaseOfDll __attribute__((in)), PCSTR Mask __attribute__((in)), PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback __attribute__((in)), PVOID UserContext __attribute__((in)));
EOS


  puts 'run_init'
  l.run_init

  puts 'sym_init'
  dl.syminitialize(42, 0, 0)
  puts 'sym_setopt'
  dl.symsetoptions(dl.symgetoptions|dl::SYMOPT_DEFERRED_LOADS|dl::SYMOPT_NO_PROMPTS)
  puts 'sym_setsearch'
  sympath = ENV['_NT_SYMBOL_PATH'] || 'srv**/tmp/symbols*http://msdl.microsoft.com/download/symbols'
  dl.symsetsearchpath(42, sympath)

  puts 'sym_loadmod'
  tg = PeLdr.new('kernel32.dll')
  dl.symloadmodule64(42, 0, 0, 0, tg.load_address, 0)

  puts 'walk'
  symstruct = [0x58].pack('L') + 0.chr*4*19 + [512].pack('L')     # sizeofstruct, ..., nameszmax
  text = tg.pe.sections.find { |s| s.name == '.text' }
  # SymEnumSymbols
  text.rawsize.times { |o|
    sym = symstruct + 0.chr*512     # name concat'ed after the struct
    off = 0.chr*8
    if dl.symfromaddr(42, tg.load_address+text.virtaddr+o, off, sym) and off.unpack('L').first == 0
      symnamelen = sym[19*4, 4].unpack('L').first
      puts ' %x %s' % [text.virtaddr+o, sym[0x54, symnamelen].inspect]
break
    end
    puts '  %x/%x' % [o, text.rawsize] if $VERBOSE and o & 0xffff == 0
  }
  puts
end
