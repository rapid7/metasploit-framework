#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# a preleminary attempt to use MS dbghelp.dll to retrieve PE symbols

require 'metasm'

dll = 'C:\\Program Files\\Debugging Tools For Windows (x86)\\dbghelp.dll'

Metasm::DynLdr.new_api_c <<EOS, dll
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

#SYMOPT = 4|0x80000	# defered_load no_prompt
#Metasm::WinAPI.new_api dll, 'SymInitialize', 'III I'
#Metasm::WinAPI.new_api dll, 'SymGetOptions', 'I'
#Metasm::WinAPI.new_api dll, 'SymSetOptions', 'I I'
#Metasm::WinAPI.new_api dll, 'SymSetSearchPath', 'IP I'
#Metasm::WinAPI.new_api dll, 'SymLoadModule64', 'IIPIIII I'	# ???ull?
#Metasm::WinAPI.new_api dll, 'SymFromAddr', 'IIIPP I'	# handle ull_addr poffset psym

class Tracer < Metasm::WinDbgAPI
  def initialize(*a)
    super(*a)
    loop
    puts 'finished'
  end

  def handler_newprocess(pid, tid, info)
    puts "newprocess: init symsrv"

    h = @hprocess[pid]
    dl = Metasm::DynLdr
    dl.syminitialize(h, 0, 0)
    dl.symsetoptions(dl.symgetoptions|dl::SYMOPT_DEFERRED_LOADS|dl::SYMOPT_NO_PROMPTS)
    sympath = ENV['_NT_SYMBOL_PATH'] || 'srv**symbols*http://msdl.microsoft.com/download/symbols'
    dl.symsetsearchpath(h, sympath.dup)	# dup cause ENV is frozen and make WinAPI raises

    Metasm::WinAPI::DBG_CONTINUE
  end

  def handler_loaddll(pid, tid, info)
    pe = Metasm::LoadedPE.load(@mem[pid][info.imagebase, 0x1000000])
    pe.decode_header
    pe.decode_exports
    return if not pe.export
    libname = pe.export.libname
    puts "loaddll: #{libname} @#{'%x' % info.imagebase}"
    h = @hprocess[pid]
    dl = Metasm::DynLdr
    dl.symloadmodule64(h, 0, libname, 0, info.imagebase, pe.optheader.image_size)
    symstruct = [0x58].pack('L') + 0.chr*4*19 + [512].pack('L')	# sizeofstruct, ..., nameszmax
    text = pe.sections.find { |s| s.name == '.text' }
    # XXX should SymEnumSymbols, but win32api callbacks sucks
    text.rawsize.times { |o|
      sym = symstruct + 0.chr*512	# name concat'ed after the struct
      off = 0.chr*8
      if dl.symfromaddr(h, info.imagebase+text.virtaddr+o, off, sym) and off.unpack('L').first == 0
        symnamelen = sym[19*4, 4].unpack('L').first
        puts ' %x %s' % [text.virtaddr+o, sym[0x54, symnamelen]]
      end
      puts '  %x/%x' % [o, text.rawsize] if $VERBOSE and o & 0xffff == 0
    }
    puts
  end
end

if $0 == __FILE__
  Metasm::WinOS.get_debug_privilege
  if ARGV.empty?
    # display list of running processes if no target found
    puts Metasm::WinOS.list_processes.sort_by { |pr_| pr_.pid }
    abort 'target needed'
  end
  pid = ARGV.shift.dup
  if pr = Metasm::WinOS.find_process(pid)
    pid = pr.pid
  end
  Tracer.new pid
end
