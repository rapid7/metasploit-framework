#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/exe_format/mz'
require 'metasm/exe_format/coff_encode'
require 'metasm/exe_format/coff_decode'

module Metasm
class PE < COFF
	PESIG = "PE\0\0"

	attr_accessor :coff_offset, :signature, :mz

	def initialize(cpu=nil)
		super(cpu)
		@mz = MZ.new(cpu).share_namespace(self)
	end

	# overrides COFF#decode_header
	# simply sets the offset to the PE pointer before decoding the COFF header
	# also checks the PE signature
	def decode_header
		@encoded.ptr = 0x3c
		@encoded.ptr = decode_word
		@signature = @encoded.read(4)
		raise InvalidExeFormat, "Invalid PE signature #{@signature.inspect}" if @signature != PESIG
		@coff_offset = @encoded.ptr
		if @mz.encoded.empty?
			@mz.encoded << @encoded[0, @coff_offset-4]
			@mz.encoded.ptr = 0
			@mz.decode_header
		end
		super
	end

	# creates a default MZ file to be used in the PE header
	# this one is specially crafted to fit in the 0x3c bytes before the signature
	def encode_default_mz_header
		# XXX use single-quoted source, to avoid ruby interpretation of \r\n
		@mz.cpu = Ia32.new(386, 16)
		@mz.parse <<'EOMZSTUB'
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
		@mz.assemble

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
		@signature ||= PESIG
		@encoded << @signature

		super
	end

	# a returns a new PE with only minimal information copied:
	#  section name/perm/addr/content
	#  exports
	#  imports (with boundimport cleared)
	#  resources
	def mini_copy
		ret = self.class.new(@cpu)
		ret.header.machine = @header.machine
		ret.optheader.entrypoint = @optheader.entrypoint
		ret.optheader.image_base = @optheader.image_base
		@sections.each { |s|
			rs = Section.new
			rs.name = s.name
			rs.virtaddr = s.virtaddr
			rs.characteristics = s.characteristics
			rs.encoded = s.encoded
			ret.sections << s
		}
		ret.resource = @resource
		if @imports
			ret.imports = @imports.map { |id| id.dup }
			ret.imports.each { |id|
				id.timestamp = id.firstforwarder =
				id.ilt_p = id.libname_p = nil
			}
		end
		ret.export = @export
		ret
	end

	def c_set_default_entrypoint
		return if @optheader.entrypoint
		if @sections.find { |s| s.encoded.export['main'] }
			@optheader.entrypoint = 'main'
		elsif @sections.find { |s| s.encoded.export['DllEntryPoint'] }
			@optheader.entrypoint = 'DllEntryPoint'
		elsif @sections.find { |s| s.encoded.export['DllMain'] }
			cp = @cpu.new_cparser
			cp.parse <<EOS
enum { DLL_PROCESS_DETACH, DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH, DLL_PROCESS_VERIFIER };
__stdcall int DllMain(void *handle, unsigned long reason, void *reserved);
__stdcall int DllEntryPoint(void *handle, unsigned long reason, void *reserved) {
	int ret = DllMain(handle, reason, reserved);
	if (ret == 0 && reason == DLL_PROCESS_ATTACH)
		DllMain(handle, DLL_PROCESS_DETACH, reserved);
	return ret;
}
EOS
			parse(@cpu.new_ccompiler(cp, self).compile)
			assemble
			@optheader.entrypoint = 'DllEntryPoint'
		elsif @sections.find { |s| s.encoded.export['WinMain'] }
			cp = @cpu.new_cparser
			cp.parse <<EOS
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
			parse(@cpu.new_ccompiler(cp, self).compile)
			assemble
			@optheader.entrypoint = 'main'
		end
	end

	# handles writes to fs:[0] -> dasm SEH handler (first only, does not follow the chain)
	# TODO seh prototype (args => context)
	# TODO hook on (non)resolution of :w xref
	def get_xrefs_x(dasm, di)
		if @cpu.kind_of? Ia32 and a = di.instruction.args.first and a.kind_of? Ia32::ModRM and a.seg and a.seg.val == 4 and
				w = get_xrefs_rw(dasm, di).find { |type, ptr, len| type == :w and ptr.externals.include? 'segment_base_fs' } and
				dasm.backtrace(Expression[w[1], :-, 'segment_base_fs'], di.address) == [Expression[0]]
			sehptr = w[1]
			sz = @cpu.size/8
			sehptr = Indirection.new(Expression[Indirection.new(sehptr, sz, di.address), :+, sz], sz, di.address)
			a = dasm.backtrace(sehptr, di.address, :include_start => true, :origin => di.address, :type => :x, :detached => true)
puts "backtrace seh from #{di} => #{a.map { |addr| Expression[addr] }.join(', ')}" if $VERBOSE
			a.each { |aa|
				next if aa == Expression::Unknown
				l = dasm.label_at(aa, 'seh', 'loc', 'sub')
				dasm.addrs_todo << [aa] 
			}
			super
		else
			super
		end
	end

	# returns a disassembler with a special decodedfunction for GetProcAddress (i386 only), and the default func
	def init_disassembler
		d = super
		d.backtrace_maxblocks_data = 4
		if @cpu.kind_of? Ia32
			old_cp = d.c_parser
			d.c_parser = nil
			d.parse_c '__stdcall void *GetProcAddress(int, char *);'
			gpa = @cpu.decode_c_function_prototype(d.c_parser, 'GetProcAddress')
			d.c_parser = old_cp
			@getprocaddr_unknown = []
			gpa.btbind_callback = proc { |dasm, bind, funcaddr, calladdr, expr, origin, maxdepth|
				next bind if @getprocaddr_unknown.include? [dasm, calladdr]
				sz = @cpu.size/8
				raise 'getprocaddr call error' if not dasm.decoded[calladdr]
				fnaddr = dasm.backtrace(Indirection.new(Expression[:esp, :+, 2*sz], sz, calladdr), calladdr, :include_start => true, :maxdepth => maxdepth)
				if fnaddr.kind_of? ::Array and fnaddr.length == 1 and s = dasm.get_section_at(fnaddr.first) and fn = s[0].read(64) and i = fn.index(0) and i > sz	# try to avoid ordinals
					bind = bind.merge :eax => Expression[fn[0, i]]
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
end

# an instance of a PE file, loaded in memory
# just change the rva_to_off and the section content decoding methods
class LoadedPE < PE
	# just check the bounds / check for 0
	def rva_to_off(rva)
		rva if rva and rva > 0 and rva <= @encoded.virtsize
	end

	# use the virtualaddr/virtualsize fields of the section header
	def decode_sections
		@sections.each { |s|
			s.encoded = @encoded[s.virtaddr, s.virtsize]
		}
	end

	# returns a PE which should give us back when loaded
	# TODO rebuild imports + revert base relocations
	def dump(baseaddr = @optheader.image_base, oep = baseaddr + @optheader.entrypoint)
		pe = PE.new
		pe.optheader.entrypoint = oep - baseaddr
		pe.optheader.image_base = @optheader.image_base
		@sections.each { |s|
			ss = Section.new
			ss.name = s.name
			ss.virtaddr = s.virtaddr
			ss.encoded = s.encoded
			ss.characteristics = s.characteristics
			pe.sections << s
		}
		# pe.imports
		# pe.relocations
		pe
	end
end
end
