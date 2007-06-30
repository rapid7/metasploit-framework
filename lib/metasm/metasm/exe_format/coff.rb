#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'

module Metasm
# the COFF object file format
# mostly used on windows (PE/COFF)
class COFF < ExeFormat
	CHARACTERISTIC_BITS = {
		0x0001 => 'RELOCS_STRIPPED',    0x0002 => 'EXECUTABLE_IMAGE',
		0x0004 => 'LINE_NUMS_STRIPPED', 0x0008 => 'LOCAL_SYMS_STRIPPED',
		0x0010 => 'AGGRESSIVE_WS_TRIM', 0x0020 => 'LARGE_ADDRESS_AWARE',
		0x0040 => 'x16BIT_MACHINE',     0x0080 => 'BYTES_REVERSED_LO',
		0x0100 => 'x32BIT_MACHINE',     0x0200 => 'DEBUG_STRIPPED',
		0x0400 => 'REMOVABLE_RUN_FROM_SWAP', 0x0800 => 'NET_RUN_FROM_SWAP',
		0x1000 => 'SYSTEM',             0x2000 => 'DLL',
		0x4000 => 'UP_SYSTEM_ONLY',     0x8000 => 'BYTES_REVERSED_HI'
	}

	MACHINE = {
		0x0   => 'UNKNOWN',   0x184 => 'ALPHA',   0x1c0 => 'ARM',
		0x1d3 => 'AM33',      0x8664=> 'AMD64',   0xebc => 'EBC',
		0x9041=> 'M32R',      0x1f1 => 'POWERPCFP',
		0x284 => 'ALPHA64',   0x14c => 'I386',    0x200 => 'IA64',
		0x268 => 'M68K',      0x266 => 'MIPS16',  0x366 => 'MIPSFPU',
		0x466 => 'MIPSFPU16', 0x1f0 => 'POWERPC', 0x162 => 'R3000',
		0x166 => 'R4000',     0x168 => 'R10000',  0x1a2 => 'SH3',
		0x1a3 => 'SH3DSP',    0x1a6 => 'SH4',     0x1a8 => 'SH5',
		0x1c2 => 'THUMB',     0x169 => 'WCEMIPSV2'
	}

	# PE+ is for 64bits address spaces
	SIGNATURE = { 0x10b => 'PE', 0x20b => 'PE+', 0x107 => 'ROM' }

	SUBSYSTEM = {
		0 => 'UNKNOWN',     1 => 'NATIVE',    2 => 'WINDOWS_GUI',
		3 => 'WINDOWS_CUI', 5 => 'OS/2_CUI',  7 => 'POSIX_CUI',
		8 => 'WIN9X_DRIVER', 9 => 'WINDOWS_CE_GUI',
		10 => 'EFI_APPLICATION',
		11 => 'EFI_BOOT_SERVICE_DRIVER',  12 => 'EFI_RUNTIME_DRIVER',
		13 => 'EFI_ROM', 14 => 'XBOX'
	}

	DLL_CHARACTERISTIC_BITS = {
		0x40 => 'DYNAMIC_BASE', 0x80 => 'FORCE_INTEGRITY', 0x100 => 'NX_COMPAT',
		0x200 => 'NO_ISOLATION', 0x400 => 'NO_SEH', 0x800 => 'NO_BIND',
		0x2000 => 'WDM_DRIVER', 0x8000 => 'TERMINAL_SERVER_AWARE'
	}
	
	BASE_RELOCATION_TYPE = { 0 => 'ABSOLUTE', 1 => 'HIGH', 2 => 'LOW', 3 => 'HIGHLOW',
		4 => 'HIGHADJ', 5 => 'MIPS_JMPADDR', 9 => 'MIPS_JMPADDR16', 10 => 'DIR64'
	}

	RELOCATION_TYPE = Hash.new({}).merge(
		'x64' => { 0 => 'ABSOLUTE', 1 => 'ADDR64', 2 => 'ADDR32', 3 => 'ADDR32NB',
			4 => 'REL32', 5 => 'REL32_1', 6 => 'REL32_2', 7 => 'REL32_3',
			8 => 'REL32_4', 9 => 'REL32_5', 10 => 'SECTION', 11 => 'SECREL',
			12 => 'SECREL7', 13 => 'TOKEN', 14 => 'SREL32', 15 => 'PAIR',
			16 => 'SSPAN32' },
		'arm' => { 0 => 'ABSOLUTE', 1 => 'ADDR32', 2 => 'ADDR32NB', 3 => 'BRANCH24',
			4 => 'BRANCH11', 14 => 'SECTION', 15 => 'SECREL' },
		'I386' => { 0 => 'ABSOLUTE', 1 => 'DIR16', 2 => 'REL16', 6 => 'DIR32',
			7 => 'DIR32NB', 9 => 'SEG12', 10 => 'SECTION', 11 => 'SECREL',
			12 => 'TOKEN', 13 => 'SECREL7', 20 => 'REL32' }
	)

	# lsb of symbol type, unused
	SYMBOL_TYPE = { 0 => 'NULL', 1 => 'VOID', 2 => 'CHAR', 3 => 'SHORT',
		4 => 'INT', 5 => 'LONG', 6 => 'FLOAT', 7 => 'DOUBLE', 8 => 'STRUCT',
		9 => 'UNION', 10 => 'ENUM', 11 => 'MOE', 12 => 'BYTE', 13 => 'WORD',
		14 => 'UINT', 15 => 'DWORD'}
	# msb of symbol type, onlf 0x20 used
	SYMBOL_DTYPE = { 0 => 'NULL', 1 => 'POINTER', 2 => 'FUNCTION', 3 => 'ARRAY' }

	DEBUG_TYPE = { 0 => 'UNKNOWN', 1 => 'COFF', 2 => 'CODEVIEW', 3 => 'FPO', 4 => 'MISC',
		5 => 'EXCEPTION', 6 => 'FIXUP', 7 => 'OMAP_TO_SRC', 8 => 'OMAP_FROM_SRC',
		9 => 'BORLAND', 10 => 'RESERVED10', 11 => 'CLSID' }

	DIRECTORIES = %w[export_table import_table resource_table exception_table certificate_table
			  base_relocation_table debug architecture global_ptr tls_table load_config
			  bound_import iat delay_import com_runtime reserved]

	SECTION_CHARACTERISTIC_BITS = {
		0x20 => 'CONTAINS_CODE', 0x40 => 'CONTAINS_DATA', 0x80 => 'CONTAINS_UDATA',
		0x100 => 'LNK_OTHER', 0x200 => 'LNK_INFO', 0x800 => 'LNK_REMOVE',
		0x1000 => 'LNK_COMDAT', 0x8000 => 'GPREL',
		0x20000 => 'MEM_PURGEABLE|16BIT', 0x40000 => 'MEM_LOCKED', 0x80000 => 'MEM_PRELOAD',
		0x100000 => 'ALIGN_1BYTES',    0x200000 => 'ALIGN_2BYTES',
		0x300000 => 'ALIGN_4BYTES',    0x400000 => 'ALIGN_8BYTES',
		0x500000 => 'ALIGN_16BYTES',   0x600000 => 'ALIGN_32BYTES',
		0x700000 => 'ALIGN_64BYTES',   0x800000 => 'ALIGN_128BYTES',
		0x900000 => 'ALIGN_256BYTES',  0xA00000 => 'ALIGN_512BYTES',
		0xB00000 => 'ALIGN_1024BYTES', 0xC00000 => 'ALIGN_2048BYTES',
		0xD00000 => 'ALIGN_4096BYTES', 0xE00000 => 'ALIGN_8192BYTES',
		0x01000000 => 'LNK_NRELOC_OVFL', 0x02000000 => 'MEM_DISCARDABLE',
		0x04000000 => 'MEM_NOT_CACHED',  0x08000000 => 'MEM_NOT_PAGED',
		0x10000000 => 'MEM_SHARED',      0x20000000 => 'MEM_EXECUTE',
		0x40000000 => 'MEM_READ',        0x80000000 => 'MEM_WRITE'
	}
	# NRELOC_OVFL means there are more than 0xffff reloc
	# the reloc count must be set to 0xffff, and the real reloc count
	# is the VA of the first relocation

	ORDINAL_REGEX = /^Ordinal_(\d+)$/

	class Header
		attr_accessor :machine, :num_sect, :time, :ptr_sym, :num_sym, :size_opthdr, :characteristics
	end

	# present in linked files (exe/dll/kmod)
	class OptionalHeader
		attr_accessor :signature, :link_ver_maj, :link_ver_min, :code_size, :idata_size, :udata_size, :entrypoint, :base_of_code,
			:base_of_data,	# not in PE+
			# NT-specific fields
			:image_base, :sect_align, :file_align, :os_ver_maj, :os_ver_min, :img_ver_maj, :img_ver_min, :subsys_maj, :subsys_min, :reserved,
			:image_size, :headers_size, :checksum, :subsystem, :dll_characts, :stack_reserve, :stack_commit, :heap_reserve, :heap_commit, :ldrflags, :numrva
	end

	# contains the name of dynamic libraries required by the program, and the function to import from them
	class ImportDirectory
		attr_accessor :libname, :timestamp, :firstforwarder, :libname_p
		attr_accessor :imports, :iat, :iat_p, :ilt_p

		class Import
			attr_accessor :ordinal, :hint, :hintname_p, :name, :target, :thunk
		end
	end

	# lists the functions/addresses exported to the OS (pendant of ImportDirectory)
	class ExportDirectory
		attr_accessor :reserved, :timestamp, :ver_maj, :ver_min, :libname, :ordinal_base, :libname_p
		attr_accessor :exports

		class Export
			attr_accessor :forwarder_lib, :forwarder_ordinal, :forwarder_name, :target, :name_p, :name, :ordinal
		end
	end

	# array of relocations to apply to an executable file when it is loaded at an address that is not its preferred_base_address
	class RelocationTable
		attr_accessor :base_addr
		attr_accessor :relocs

		class Relocation
			attr_accessor :offset, :type
		end
	end

	# section table information, + raw section content (EncodedData)
	class Section
		attr_accessor :name, :virtsize, :virtaddr, :rawsize, :rawaddr, :relocaddr, :linenoaddr, :relocnr, :linenonr, :characteristics
		attr_accessor :encoded
	end
	
	# the 'load configuration' directory
	class LoadConfig
		attr_accessor :signature, :timestamp, :major_version, :minor_version, :globalflags, :critsec_timeout,
			:decommitblock, :decommittotal, :lockpfxtable, :maxalloc, :maxvirtmem, :process_affinity_mask, :process_heap_flags,
			:servicepackid, :reserved, :editlist,
			:security_cookie, :sehtable_p, :sehcount
		attr_accessor :safeseh
	end

	# tree-like structure, holds all misc data the program might need (icons, cursors, version information)
	# conventionnally structured in a 3-level depth structure:
	#  I resource type (icon/cursor/etc, see +TYPES+)
	#  II resource id (icon n1, icon 'toto', ...)
	#  III language-specific version (icon n1 en, icon n1 en-dvorak...)
	# for the icon, the one that appears in the explorer is
	#  (NT) the one with the lowest ID
	#  (98) the first to appear in the table
	class ResourceDirectory
		attr_accessor :characteristics, :timestamp, :major_version, :minor_version
		attr_accessor :entries
		attr_accessor :curoff_label	# internal use, in encoder

		class Entry
			attr_accessor :name_p, :name, :name_w,
				:id, :subdir_p, :subdir, :dataentry_p,
				:data_p, :data, :codepage, :reserved
		end

		def to_hash
			@entries.inject({}) { |h, e|
				k = e.id ? e.id : e.name ? e.name : e.name_w
				v = e.subdir ? e.subdir.to_hash : e.data
				h.update k => v
			}
		end

		def self.from_hash(h)
			ret = new
			ret.entries = h.map { |k, v|
				e = Entry.new
				k.kind_of?(Integer) ? (e.id = k) : (e.name = k)	# name_w ?
				v.kind_of?(Hash) ? (e.subdir = from_hash(v)) : (e.data = v)
				e
			}
			ret
		end

		TYPE = {
			1 => 'CURSOR', 2 => 'BITMAP', 3 => 'ICON', 4 => 'MENU',
			5 => 'DIALOG', 6 => 'STRING', 7 => 'FONTDIR', 8 => 'FONT',
			9 => 'ACCELERATOR', 10 => 'RCADATA', 11 => 'MESSAGETABLE',
			12 => 'GROUP_CURSOR', 14 => 'GROUP_ICON', 16 => 'VERSION',
			17 => 'DLGINCLUDE', 19 => 'PLUGPLAY', 20 => 'VXD',
			21 => 'ANICURSOR', 22 => 'ANIICON', 23 => 'HTML',
			24 => 'MANIFEST' # ?
		}

		ACCELERATOR_BITS = {
			1 => 'VIRTKEY', 2 => 'NOINVERT', 4 => 'SHIFT', 8 => 'CTRL',
			16 => 'ALT', 128 => 'LAST'
		}

		# cursor = raw data, cursor_group = header , pareil pour les icons
		class Cursor
			attr_accessor :xhotspot, :yhotspot, :data
		end
	end

	attr_accessor :header, :optheader, :directory, :sections, :endianness, :export, :imports,
		:relocations, :resource, :certificates, :delayimports, :loadconfig

	def initialize(cpu=nil)
		@directory = {}	# DIRECTORIES.key => [rva, size]
		@sections = []
		@export = @imports = @relocations = @resource = @certificates = @delayimports = nil
		@endianness = cpu ? cpu.endianness : :little
		@header = Header.new
		@optheader = OptionalHeader.new
		@header.machine = case cpu
		when nil: 'UNKNOWN'
		when Ia32: 'I386'
		else 'UNKNOWN'
		end
		super(cpu)
	end
end

# the COFF archive file format
# may be used in .lib files (they hold binary import information for libraries)
class COFFArchive < ExeFormat
	class Member
		attr_accessor :name, :date, :uid, :gid, :mode, :size, :eoh
		attr_accessor :offset
	end

	class ImportHeader
		attr_accessor :sig1, :sig2, :version, :machine, :timestamp, :size_of_data, :hint, :type, :name_type, :reserved
		attr_accessor :symname, :libname
	end

	attr_accessor :members, :signature, :first_linker, :second_linker
end
end
__END__

class Symbols
	attr_reader :name, :value, :sectionnumber, :type, :storageclass, :nbaux, :aux
# name: if the first 4 bytes are null, the 4 next are the index to the name in the string table

	def initialize(raw, offset)
		@name = raw[offset..offset+7].delete("\0")
		@value = bin(raw[offset+8 ..offset+11])
		@sectionnumber = bin(raw[offset+12..offset+13])
		@type = bin(raw[offset+14..offset+15])
		@storageclass = raw[offset+16]
		@nbaux = raw[offset+17]
		@aux = Array.new
		@nbaux.times { @aux << raw[offset..offset+17] ; offset += 18 }
	end
end

class Strings < Array
	attr_reader :size
	
	def initialize(raw, offset)
		@size = bin(raw[offset..offset+3])
		endoffset = offset + @size
puts "String table: 0x%.8x .. 0x%.8x" % [offset, endoffset]
		curstring = ''
		while (offset < endoffset)
			if raw[offset] != 0
				curstring << raw[offset]
			else
				self << curstring
				curstring = ''
			end
			offset += 1
		end
	end
end
