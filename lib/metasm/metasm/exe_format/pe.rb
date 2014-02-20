#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/exe_format/mz'
require 'metasm/exe_format/coff'

module Metasm
class PE < COFF
  MAGIC = "PE\0\0"	# 0x50450000

  attr_accessor :coff_offset, :signature, :mz

  def initialize(*a)
    super(*a)
    cpu = a.grep(CPU).first
    @mz = MZ.new(cpu).share_namespace(self)
  end

  # overrides COFF#decode_header
  # simply sets the offset to the PE pointer before decoding the COFF header
  # also checks the PE signature
  def decode_header
    @cursection ||= self
    @encoded.ptr = 0x3c
    @encoded.ptr = decode_word(@encoded)
    @signature = @encoded.read(4)
    raise InvalidExeFormat, "Invalid PE signature #{@signature.inspect}" if @signature != MAGIC
    @coff_offset = @encoded.ptr
    if @mz.encoded.empty?
      @mz.encoded << @encoded[0, @coff_offset-4]
      @mz.encoded.ptr = 0
      @mz.decode_header
    end
    super()
  end

  # creates a default MZ file to be used in the PE header
  # this one is specially crafted to fit in the 0x3c bytes before the signature
  def encode_default_mz_header
    # XXX use single-quoted source, to avoid ruby interpretation of \r\n
    @mz.cpu = Ia32.new(386, 16)
    @mz.assemble <<'EOMZSTUB'
  db "Needs Win32!\r\n$"
.entrypoint
  push cs
  pop  ds
  xor  dx, dx	  ; ds:dx = addr of $-terminated string
  mov  ah, 9        ; output string
  int  21h
  mov  ax, 4c01h    ; exit with code in al
  int  21h
EOMZSTUB

    mzparts = @mz.pre_encode

    # put stuff before 0x3c
    @mz.encoded << mzparts.shift
    raise 'OH NOES !!1!!!1!' if @mz.encoded.virtsize > 0x3c	# MZ header is too long, cannot happen
    until mzparts.empty?
      break if mzparts.first.virtsize + @mz.encoded.virtsize > 0x3c
      @mz.encoded << mzparts.shift
    end

    # set PE signature pointer
    @mz.encoded.align 0x3c
    @mz.encoded << encode_word('pesigptr')

    # put last parts of the MZ program
    until mzparts.empty?
      @mz.encoded << mzparts.shift
    end

    # ensure the sig will be 8bytes-aligned
    @mz.encoded.align 8

    @mz.encoded.fixup 'pesigptr' => @mz.encoded.virtsize
    @mz.encoded.fixup @mz.encoded.binding
    @mz.encoded.fill
    @mz.encode_fix_checksum
  end

  # encodes the PE header before the COFF header, uses a default mz header if none defined
  # the MZ header must have 0x3c pointing just past its last byte which should be 8bytes aligned
  # the 2 1st bytes of the MZ header should be 'MZ'
  def encode_header(*a)
    encode_default_mz_header if @mz.encoded.empty?

    @encoded << @mz.encoded.dup

    # append the PE signature
    @signature ||= MAGIC
    @encoded << @signature

    super(*a)
  end

  # a returns a new PE with only minimal information copied:
  #  section name/perm/addr/content
  #  exports
  #  imports (with boundimport cleared)
  #  resources
  def mini_copy(share_ns=true)
    ret = self.class.new(@cpu)
    ret.share_namespace(self) if share_ns
    ret.header.machine = @header.machine
    ret.header.characteristics = @header.characteristics
    ret.optheader.entrypoint = @optheader.entrypoint
    ret.optheader.image_base = @optheader.image_base
    ret.optheader.subsystem  = @optheader.subsystem
    ret.optheader.dll_characts = @optheader.dll_characts
    @sections.each { |s|
      rs = Section.new
      rs.name = s.name
      rs.virtaddr = s.virtaddr
      rs.characteristics = s.characteristics
      rs.encoded = s.encoded
      ret.sections << s
    }
    ret.resource = resource
    ret.tls = tls
    if imports
      ret.imports = @imports.map { |id| id.dup }
      ret.imports.each { |id|
        id.timestamp = id.firstforwarder =
        id.ilt_p = id.libname_p = nil
      }
    end
    ret.export = export
    ret
  end

  def c_set_default_entrypoint
    return if @optheader.entrypoint
    if @sections.find { |s| s.encoded.export['main'] }
      @optheader.entrypoint = 'main'
    elsif @sections.find { |s| s.encoded.export['DllEntryPoint'] }
      @optheader.entrypoint = 'DllEntryPoint'
    elsif @sections.find { |s| s.encoded.export['DllMain'] }
      case @cpu.shortname
      when 'ia32'
        @optheader.entrypoint = 'DllEntryPoint'
        compile_c <<EOS
enum { DLL_PROCESS_DETACH, DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH, DLL_PROCESS_VERIFIER };
__stdcall int DllMain(void *handle, unsigned long reason, void *reserved);
__stdcall int DllEntryPoint(void *handle, unsigned long reason, void *reserved) {
  int ret = DllMain(handle, reason, reserved);
  if (ret == 0 && reason == DLL_PROCESS_ATTACH)
    DllMain(handle, DLL_PROCESS_DETACH, reserved);
  return ret;
}
EOS
      else
        @optheader.entrypoint = 'DllMain'
      end
    elsif @sections.find { |s| s.encoded.export['WinMain'] }
      case @cpu.shortname
      when 'ia32'
        @optheader.entrypoint = 'main'
        compile_c <<EOS
#define GetCommandLine GetCommandLineA
#define GetModuleHandle GetModuleHandleA
#define GetStartupInfo GetStartupInfoA
#define STARTF_USESHOWWINDOW 0x00000001
#define SW_SHOWDEFAULT 10

typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef struct {
  DWORD cb; char *lpReserved, *lpDesktop, *lpTitle;
  DWORD dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
  WORD wShowWindow, cbReserved2; char *lpReserved2;
  void *hStdInput, *hStdOutput, *hStdError;
} STARTUPINFO;

__stdcall void *GetModuleHandleA(const char *lpModuleName);
__stdcall void GetStartupInfoA(STARTUPINFO *lpStartupInfo);
__stdcall void ExitProcess(unsigned int uExitCode);
__stdcall char *GetCommandLineA(void);
__stdcall int WinMain(void *hInstance, void *hPrevInstance, char *lpCmdLine, int nShowCmd);

int main(void) {
  STARTUPINFO startupinfo;
  startupinfo.cb = sizeof(STARTUPINFO);
  char *cmd = GetCommandLine();
  int ret;

  if (*cmd == '"') {
    cmd++;
    while (*cmd && *cmd != '"') {
      if (*cmd == '\\\\') cmd++;
      cmd++;
    }
    if (*cmd == '"') cmd++;
  } else
    while (*cmd && *cmd != ' ') cmd++;
  while (*cmd == ' ') cmd++;

  GetStartupInfo(&startupinfo);
  ret = WinMain(GetModuleHandle(0), 0, cmd, (startupinfo.dwFlags & STARTF_USESHOWWINDOW) ? (int)startupinfo.wShowWindow : (int)SW_SHOWDEFAULT);
  ExitProcess((DWORD)ret);
  return ret;
}
EOS
      else
        @optheader.entrypoint = 'WinMain'
      end
    end
  end

  # handles writes to fs:[0] -> dasm SEH handler (first only, does not follow the chain)
  # TODO seh prototype (args => context)
  # TODO hook on (non)resolution of :w xref
  def get_xrefs_x(dasm, di)
    if @cpu.shortname =~ /ia32|x64/ and a = di.instruction.args.first and a.kind_of? Ia32::ModRM and a.seg and a.seg.val == 4 and
        w = get_xrefs_rw(dasm, di).find { |type, ptr, len| type == :w and ptr.externals.include? 'segment_base_fs' } and
        dasm.backtrace(Expression[w[1], :-, 'segment_base_fs'], di.address).to_a.include?(Expression[0])
      sehptr = w[1]
      sz = @cpu.size/8
      sehptr = Indirection.new(Expression[Indirection.new(sehptr, sz, di.address), :+, sz], sz, di.address)
      a = dasm.backtrace(sehptr, di.address, :include_start => true, :origin => di.address, :type => :x, :detached => true)
      puts "backtrace seh from #{di} => #{a.map { |addr| Expression[addr] }.join(', ')}" if $VERBOSE
      a.each { |aa|
        next if aa == Expression::Unknown
        l = dasm.auto_label_at(aa, 'seh', 'loc', 'sub')
        dasm.addrs_todo << [aa]
      }
      super(dasm, di)
    else
      super(dasm, di)
    end
  end

  # returns a disassembler with a special decodedfunction for GetProcAddress (i386 only), and the default func
  def init_disassembler
    d = super()
    d.backtrace_maxblocks_data = 4
    case @cpu.shortname
    when 'ia32', 'x64'
      old_cp = d.c_parser
      d.c_parser = nil
      d.parse_c '__stdcall void *GetProcAddress(int, char *);'
      d.c_parser.lexer.define_weak('__MS_X86_64_ABI__') if @cpu.kind_of? X86_64
      gpa = @cpu.decode_c_function_prototype(d.c_parser, 'GetProcAddress')
      d.c_parser = old_cp
      d.parse_c ''
      d.c_parser.lexer.define_weak('__MS_X86_64_ABI__') if @cpu.kind_of? X86_64
      @getprocaddr_unknown = []
      gpa.btbind_callback = lambda { |dasm, bind, funcaddr, calladdr, expr, origin, maxdepth|
        break bind if @getprocaddr_unknown.include? [dasm, calladdr] or not Expression[expr].externals.include? :eax
        sz = @cpu.size/8
        break bind if not dasm.decoded[calladdr]
        if @cpu.kind_of? X86_64
          arg2 = :rdx
        else
          arg2 = Indirection[[:esp, :+, 2*sz], sz, calladdr]
        end
        fnaddr = dasm.backtrace(arg2, calladdr, :include_start => true, :maxdepth => maxdepth)
        if fnaddr.kind_of? ::Array and fnaddr.length == 1 and s = dasm.get_section_at(fnaddr.first) and fn = s[0].read(64) and i = fn.index(?\0) and i > sz	# try to avoid ordinals
          bind = bind.merge @cpu.register_symbols[0] => Expression[fn[0, i]]
        else
          @getprocaddr_unknown << [dasm, calladdr]
          puts "unknown func name for getprocaddress from #{Expression[calladdr]}" if $VERBOSE
        end
        bind
      }
      d.function[Expression['GetProcAddress']] = gpa
      d.function[:default] = @cpu.disassembler_default_func
    end
    d
  end

  def module_name
    export and @export.libname
  end

  def module_address
    @optheader.image_base
  end

  def module_size
    @sections.map { |s_| s_.virtaddr + s_.virtsize }.max || 0
  end

  def module_symbols
    syms = [['entrypoint', @optheader.entrypoint]]
    @export.exports.to_a.each { |e|
      next if not e.target
      name = e.name || "ord_#{e.ordinal}"
      syms << [name, label_rva(e.target)]
    } if export
    syms
  end
end

# an instance of a PE file, loaded in memory
# just change the rva_to_off and the section content decoding methods
class LoadedPE < PE
  attr_accessor :load_address

  # use the virtualaddr/virtualsize fields of the section header
  def decode_section_body(s)
    s.encoded = @encoded[s.virtaddr, s.virtsize] || EncodedData.new
  end

  # no need to decode relocations on an already mapped image
  def decode_relocs
  end

  # reads a loaded PE from memory, returns a PE object
  # dumps the header, optheader and all sections ; try to rebuild IAT (#memdump_imports)
  def self.memdump(memory, baseaddr, entrypoint = nil, iat_p=nil)
    loaded = LoadedPE.load memory[baseaddr, 0x1000_0000]
    loaded.load_address = baseaddr
    loaded.decode

    dump = PE.new(loaded.cpu_from_headers)
    dump.share_namespace loaded
    dump.optheader.image_base = baseaddr
    dump.optheader.entrypoint = (entrypoint || loaded.optheader.entrypoint + baseaddr) - baseaddr
    dump.directory['resource_table'] = loaded.directory['resource_table']

    loaded.sections.each { |s|
      ss = Section.new
      ss.name = s.name
      ss.virtaddr = s.virtaddr
      ss.encoded = s.encoded
      ss.characteristics = s.characteristics
      dump.sections << ss
    }

    loaded.memdump_imports(memory, dump, iat_p)

    dump
  end

  # rebuilds an IAT from the loaded pe and the memory
  #  for each loaded iat, find the matching dll in memory
  #  for each loaded iat entry, retrieve the exported name from the loaded dll
  # OR
  #  from a base iat address in memory (unk_iat_p, rva), retrieve the 1st dll, find
  #  all iat pointers/forwarders to this dll, on failure try to find another dll
  #  allows gaps of 5 invalid pointers between libraries
  # dll found by scanning pages 16 by 16 backward from the first iat address (XXX the 1st must not be forwarded)
  # TODO bound imports
  def memdump_imports(memory, dump, unk_iat_p=nil)
    puts 'rebuilding imports...' if $VERBOSE
    if unk_iat_p
      # read iat data from unk_iat_p
      iat_p = unk_iat_p
    else
      return if not imports
      # read iat data from @imports
      imports = @imports.dup
      imports.each { |id| id.iat = id.iat.dup }
      iat_p = imports.first.iat_p	# used for iat_p
    end

    failcnt = 0		# bad pointers in iat table (unk_ only)
    dump.imports ||= []
    loaded_dll = nil	# the dll from who we're importing the current importdirectory
    ptrsz = (@optheader.signature == 'PE+' ? 8 : 4)
    cache = []	# optimize forwarder target search
    loop do
      if unk_iat_p
        # read imported pointer from the table
        ptr = decode_xword(EncodedData.new(memory[@load_address + iat_p, ptrsz]))
        iat_p += ptrsz
      else
        # read imported pointer from the import structure
        while not ptr = imports.first.iat.shift
          load_dll = nil
          imports.shift
          break if imports.empty?
          iat_p = imports.first.iat_p
        end
        break if imports.empty?
        iat_p += ptrsz
      end

      if not loaded_dll or not e = loaded_dll.export.exports.find { |e_| loaded_dll.label_rva(e_.target) == ptr - loaded_dll.load_address }
        # points to unknown space
        # find pointed module start
        if not dll = cache.find { |dll_| ptr >= dll_.load_address and ptr < dll_.load_address + dll_.optheader.image_size }
          addr = ptr & ~0xffff
          256.times { break if memory[addr, 2] == MZ::MAGIC or addr < 0x10000 ; addr -= 0x10000 }
          if memory[addr, 2] == MZ::MAGIC
            dll = LoadedPE.load memory[addr, 0x1000_0000]
            dll.load_address = addr
            dll.decode_header
            dll.decode_exports
            cache << dll
          end
        end
        if dll and dll.export and e = dll.export.exports.find { |e_| dll.label_rva(e_.target) == ptr - dll.load_address }
          if loaded_dll and ee = loaded_dll.export.exports.find { |ee_| ee_.forwarder_name == e.name }
            # it's a forwarder from the current loaded_dll
            puts "forwarder #{ee.name} -> #{dll.export.libname}!#{e.name}" if $DEBUG
            e = ee
          else
            # new library, start a new importdirectory
            # XXX if 1st import is forwarded, loaded_dll will points to the bad module...
            loaded_dll = dll
            id = ImportDirectory.new
            id.libname = loaded_dll.export.libname
            puts "lib #{id.libname}" if $VERBOSE
            id.imports = []
            id.iat_p = iat_p - ptrsz
            dump.imports << id
          end
        else
          puts 'unknown ptr %x' % ptr if $DEBUG
          # allow holes in the unk_iat_p table
          break if not unk_iat_p or failcnt > 4
          failcnt += 1
          next
        end
        failcnt = 0
      end

      # dumped last importdirectory is correct, append the import field
 			i = ImportDirectory::Import.new
      if e.name
        puts e.name if $DEBUG
        i.name = e.name
      else
        puts "##{e.ordinal}" if $DEBUG
        i.ordinal = e.ordinal
      end
      dump.imports.last.imports << i
    end
  end
end
end
