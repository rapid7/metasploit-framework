#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/peparsey/exceptions'
require 'rex/struct2'

module Rex
module PeParsey
class PeBase


	# #define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
	IMAGE_DOS_SIGNATURE = 0x5a4d

	IMAGE_DOS_HEADER_SIZE = 64
	# Struct
	#   typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	#       WORD   e_magic;                     // Magic number
	#       WORD   e_cblp;                      // Bytes on last page of file
	#       WORD   e_cp;                        // Pages in file
	#       WORD   e_crlc;                      // Relocations
	#       WORD   e_cparhdr;                   // Size of header in paragraphs
	#       WORD   e_minalloc;                  // Minimum extra paragraphs needed
	#       WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	#       WORD   e_ss;                        // Initial (relative) SS value
	#       WORD   e_sp;                        // Initial SP value
	#       WORD   e_csum;                      // Checksum
	#       WORD   e_ip;                        // Initial IP value
	#       WORD   e_cs;                        // Initial (relative) CS value
	#       WORD   e_lfarlc;                    // File address of relocation table
	#       WORD   e_ovno;                      // Overlay number
	#       WORD   e_res[4];                    // Reserved words
	#       WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	#       WORD   e_oeminfo;                   // OEM information; e_oemid specific
	#       WORD   e_res2[10];                  // Reserved words
	#       LONG   e_lfanew;                    // File address of new exe header
	#   } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
	IMAGE_DOS_HEADER = Rex::Struct2::CStructTemplate.new(
	  [ 'uint16v', 'e_magic',     IMAGE_DOS_SIGNATURE ],
	  [ 'uint16v', 'e_cblp',      0 ],
	  [ 'uint16v', 'e_cp',        0 ],
	  [ 'uint16v', 'e_crlc',      0 ],
	  [ 'uint16v', 'e_cparhdr',   0 ],
	  [ 'uint16v', 'e_minalloc',  0 ],
	  [ 'uint16v', 'e_maxalloc',  0 ],
	  [ 'uint16v', 'e_ss',        0 ],
	  [ 'uint16v', 'e_sp',        0 ],
	  [ 'uint16v', 'e_csum',      0 ],
	  [ 'uint16v', 'e_ip',        0 ],
	  [ 'uint16v', 'e_cs',        0 ],
	  [ 'uint16v', 'e_lfarlc',    0 ],
	  [ 'uint16v', 'e_ovno',      0 ],
	  [ 'template', 'e_res', Rex::Struct2::CStructTemplate.new(
	    [ 'uint16v', 'e_res_0', 0 ],
	    [ 'uint16v', 'e_res_1', 0 ],
	    [ 'uint16v', 'e_res_2', 0 ],
	    [ 'uint16v', 'e_res_3', 0 ]
	  )],
	  [ 'uint16v', 'e_oemid',     0 ],
	  [ 'uint16v', 'e_oeminfo',   0 ],
	  [ 'template', 'e_res2', Rex::Struct2::CStructTemplate.new(
	    [ 'uint16v', 'e_res2_0', 0 ],
	    [ 'uint16v', 'e_res2_1', 0 ],
	    [ 'uint16v', 'e_res2_2', 0 ],
	    [ 'uint16v', 'e_res2_3', 0 ],
	    [ 'uint16v', 'e_res2_4', 0 ],
	    [ 'uint16v', 'e_res2_5', 0 ],
	    [ 'uint16v', 'e_res2_6', 0 ],
	    [ 'uint16v', 'e_res2_7', 0 ],
	    [ 'uint16v', 'e_res2_8', 0 ],
	    [ 'uint16v', 'e_res2_9', 0 ]
	  )],
	  [ 'uint32v', 'e_lfanew',    0 ]
	)


	class HeaderAccessor
		attr_accessor :dos, :file, :opt, :sections, :config, :exceptions, :tls
		def initialize
		end
	end

	class GenericStruct
		attr_accessor :struct
		def initialize(_struct)
			self.struct = _struct
		end

		# The following methods are just pass-throughs for struct

		# Access a value
		def v
			struct.v
		end

		# Access a value by array
		def [](*args)
			struct[*args]
		end

		# Obtain an array of all fields
		def keys
			struct.keys
		end

		def method_missing(meth, *args)
			v[meth.to_s] || (raise NoMethodError.new, meth)
		end
	end

	class GenericHeader < GenericStruct
	end

	class DosHeader < GenericHeader

		def initialize(rawdata)
			dos_header = IMAGE_DOS_HEADER.make_struct

			if !dos_header.from_s(rawdata)
				raise DosHeaderError, "Couldn't parse IMAGE_DOS_HEADER", caller
			end

			if dos_header.v['e_magic'] != IMAGE_DOS_SIGNATURE
				raise DosHeaderError, "Couldn't find DOS e_magic", caller
			end

			self.struct = dos_header
		end

		def e_lfanew
			v['e_lfanew']
		end
	end


	def self._parse_dos_header(rawdata)
		return DosHeader.new(rawdata)
	end

	# #define IMAGE_NT_SIGNATURE                  0x00004550  // PE00
	IMAGE_NT_SIGNATURE       = 0x00004550
	# #define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
	IMAGE_FILE_MACHINE_I386  = 0x014c
	# #define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
	IMAGE_FILE_MACHINE_IA64  = 0x0200
	# #define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
	IMAGE_FILE_MACHINE_ALPHA64 = 0x0284
	# #define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
	IMAGE_FILE_MACHINE_AMD64 = 0x8664
	# #define IMAGE_SIZEOF_FILE_HEADER             20
	IMAGE_FILE_HEADER_SIZE   = 20+4  # because we include the signature

	# C struct defining the PE file header
	#   typedef struct _IMAGE_FILE_HEADER {
	#       WORD    Machine;
	#       WORD    NumberOfSections;
	#       DWORD   TimeDateStamp;
	#       DWORD   PointerToSymbolTable;
	#       DWORD   NumberOfSymbols;
	#       WORD    SizeOfOptionalHeader;
	#       WORD    Characteristics;
	#   } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
	IMAGE_FILE_HEADER = Rex::Struct2::CStructTemplate.new(
	  # not really in the header, but easier for us this way
	  [ 'uint32v', 'NtSignature',           0 ],
	  [ 'uint16v', 'Machine',               0 ],
	  [ 'uint16v', 'NumberOfSections',      0 ],
	  [ 'uint32v', 'TimeDateStamp',         0 ],
	  [ 'uint32v', 'PointerToSymbolTable',  0 ],
	  [ 'uint32v', 'NumberOfSymbols',       0 ],
	  [ 'uint16v', 'SizeOfOptionalHeader',  0 ],
	  [ 'uint16v', 'Characteristics',       0 ]
	)

	SUPPORTED_MACHINES = [
		IMAGE_FILE_MACHINE_I386,
		IMAGE_FILE_MACHINE_IA64,
		IMAGE_FILE_MACHINE_ALPHA64,
		IMAGE_FILE_MACHINE_AMD64
	]

	class FileHeader < GenericHeader
		def initialize(rawdata)
			file_header = IMAGE_FILE_HEADER.make_struct

			if !file_header.from_s(rawdata)
				raise FileHeaderError, "Couldn't parse IMAGE_FILE_HEADER", caller
			end

			if file_header.v['NtSignature'] != IMAGE_NT_SIGNATURE
				raise FileHeaderError, "Couldn't find the PE magic!"
			end

			if SUPPORTED_MACHINES.include?(file_header.v['Machine']) == false
				raise FileHeaderError, "Unsupported machine type: #{file_header.v['Machine']}", caller
			end

			self.struct = file_header
		end

		def Machine
			v['Machine']
		end

		def SizeOfOptionalHeader
			v['SizeOfOptionalHeader']
		end

		def NumberOfSections
			v['NumberOfSections']
		end
	end

	def self._parse_file_header(rawdata)
		return FileHeader.new(rawdata)
	end

	IMAGE_ORDINAL_FLAG32         = 0x80000000
	IMAGE_IMPORT_DESCRIPTOR_SIZE = 20
	# Struct
	#   typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	#       union {
	#           DWORD   Characteristics;            // 0 for terminating null import descriptor
	#           DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	#       };
	#       DWORD   TimeDateStamp;                  // 0 if not bound,
	#                                               // -1 if bound, and real date\time stamp
	#                                               //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	#                                               // O.W. date/time stamp of DLL bound to (Old BIND)
	#
	#       DWORD   ForwarderChain;                 // -1 if no forwarders
	#       DWORD   Name;
	#       DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
	#   } IMAGE_IMPORT_DESCRIPTOR;
	IMAGE_IMPORT_DESCRIPTOR = Rex::Struct2::CStructTemplate.new(
	  [ 'uint32v', 'OriginalFirstThunk',           0 ],
	  [ 'uint32v', 'TimeDateStamp',                0 ],
	  [ 'uint32v', 'ForwarderChain',               0 ],
	  [ 'uint32v', 'Name',                         0 ],
	  [ 'uint32v', 'FirstThunk',                   0 ]
	)

	#   typedef struct _IMAGE_IMPORT_BY_NAME {
	#       WORD    Hint;
	#       BYTE    Name[1];
	#   } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
	#

	class ImportDescriptor
		attr_accessor :name, :entries
		def initialize(_name, _entries)
			self.name    = _name
			self.entries = _entries
		end
	end

	class ImportEntry
		attr_accessor :name, :ordinal
		def initialize(_name, _ordinal)
			self.name     = _name
			self.ordinal  = _ordinal
		end
	end

	# sizeof(struct _IMAGE_EXPORT_DESCRIPTOR)
	IMAGE_EXPORT_DESCRIPTOR_SIZE = 40
	# Struct defining the export table
	#   typedef struct _IMAGE_EXPORT_DIRECTORY {
	#       DWORD   Characteristics;
	#       DWORD   TimeDateStamp;
	#       WORD    MajorVersion;
	#       WORD    MinorVersion;
	#       DWORD   Name;
	#       DWORD   Base;
	#       DWORD   NumberOfFunctions;
	#       DWORD   NumberOfNames;
	#       DWORD   AddressOfFunctions;     // RVA from base of image
	#       DWORD   AddressOfNames;         // RVA from base of image
	#       DWORD   AddressOfNameOrdinals;  // RVA from base of image
	#   } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
	IMAGE_EXPORT_DESCRIPTOR = Rex::Struct2::CStructTemplate.new(
	  [ 'uint32v', 'Characteristics',              0 ],
	  [ 'uint32v', 'TimeDateStamp',                0 ],
	  [ 'uint16v', 'MajorVersion',                 0 ],
	  [ 'uint16v', 'MinorVersion',                 0 ],
	  [ 'uint32v', 'Name',                         0 ],
	  [ 'uint32v', 'Base',                         0 ],
	  [ 'uint32v', 'NumberOfFunctions',            0 ],
	  [ 'uint32v', 'NumberOfNames',                0 ],
	  [ 'uint32v', 'AddressOfFunctions',           0 ],
	  [ 'uint32v', 'AddressOfNames',               0 ],
	  [ 'uint32v', 'AddressOfNameOrdinals',        0 ]
	)

	class ExportDirectory
		attr_accessor :name, :entries, :base

		def initialize(_name, _entries, _base)
			self.name    = _name
			self.entries = _entries
			self.base    = _base
		end
	end

	class ExportEntry
		attr_accessor :name, :ordinal, :rva
		def initialize(_name, _ordinal, _rva)
			self.name     = _name
			self.ordinal  = _ordinal
			self.rva      = _rva
		end
	end

	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_DATA_DIRECTORY_SIZE        = 8
	IMAGE_DIRECTORY_ENTRY_EXPORT         = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT         = 1
	IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2
	IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3
	IMAGE_DIRECTORY_ENTRY_SECURITY       = 4
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5
	IMAGE_DIRECTORY_ENTRY_DEBUG          = 6
	IMAGE_DIRECTORY_ENTRY_COPYRIGHT      = 7
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8
	IMAGE_DIRECTORY_ENTRY_TLS            = 9
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11
	IMAGE_DIRECTORY_ENTRY_IAT            = 12
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
	# Struct
	#   typedef struct _IMAGE_DATA_DIRECTORY {
	#       DWORD   VirtualAddress;
	#       DWORD   Size;
	#   } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
	IMAGE_DATA_DIRECTORY = Rex::Struct2::CStructTemplate.new(
	  [ 'uint32v', 'VirtualAddress',               0 ],
	  [ 'uint32v', 'Size',                         0 ]
	)

	# Struct
	#   typedef struct _IMAGE_OPTIONAL_HEADER {
	#       //
	#       // Standard fields.
	#       //
	#
	#       WORD    Magic;
	#       BYTE    MajorLinkerVersion;
	#       BYTE    MinorLinkerVersion;
	#       DWORD   SizeOfCode;
	#       DWORD   SizeOfInitializedData;
	#       DWORD   SizeOfUninitializedData;
	#       DWORD   AddressOfEntryPoint;
	#       DWORD   BaseOfCode;
	#       DWORD   BaseOfData;
	#
	#       //
	#       // NT additional fields.
	#       //
	#
	#       DWORD   ImageBase;
	#       DWORD   SectionAlignment;
	#       DWORD   FileAlignment;
	#       WORD    MajorOperatingSystemVersion;
	#       WORD    MinorOperatingSystemVersion;
	#       WORD    MajorImageVersion;
	#       WORD    MinorImageVersion;
	#       WORD    MajorSubsystemVersion;
	#       WORD    MinorSubsystemVersion;
	#       DWORD   Win32VersionValue;
	#       DWORD   SizeOfImage;
	#       DWORD   SizeOfHeaders;
	#       DWORD   CheckSum;
	#       WORD    Subsystem;
	#       WORD    DllCharacteristics;
	#       DWORD   SizeOfStackReserve;
	#       DWORD   SizeOfStackCommit;
	#       DWORD   SizeOfHeapReserve;
	#       DWORD   SizeOfHeapCommit;
	#       DWORD   LoaderFlags;
	#       DWORD   NumberOfRvaAndSizes;
	#       IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	#   } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
	#
	#   #define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
	#   #define IMAGE_SIZEOF_NT_OPTIONAL32_HEADER    224
	#

	IMAGE_NT_OPTIONAL_HDR32_MAGIC     = 0x10b
	IMAGE_SIZEOF_NT_OPTIONAL32_HEADER = 224
	IMAGE_OPTIONAL_HEADER32 = Rex::Struct2::CStructTemplate.new(
	  [ 'uint16v', 'Magic',                        0 ],
	  [ 'uint8',   'MajorLinkerVersion',           0 ],
	  [ 'uint8',   'MinorLinkerVersion',           0 ],
	  [ 'uint32v', 'SizeOfCode',                   0 ],
	  [ 'uint32v', 'SizeOfInitializeData',         0 ],
	  [ 'uint32v', 'SizeOfUninitializeData',       0 ],
	  [ 'uint32v', 'AddressOfEntryPoint',          0 ],
	  [ 'uint32v', 'BaseOfCode',                   0 ],
	  [ 'uint32v', 'BaseOfData',                   0 ],
	  [ 'uint32v', 'ImageBase',                    0 ],
	  [ 'uint32v', 'SectionAlignment',             0 ],
	  [ 'uint32v', 'FileAlignment',                0 ],
	  [ 'uint16v', 'MajorOperatingSystemVersion',  0 ],
	  [ 'uint16v', 'MinorOperatingSystemVersion',  0 ],
	  [ 'uint16v', 'MajorImageVersion',            0 ],
	  [ 'uint16v', 'MinorImageVersion',            0 ],
	  [ 'uint16v', 'MajorSubsystemVersion',        0 ],
	  [ 'uint16v', 'MinorSubsystemVersion',        0 ],
	  [ 'uint32v', 'Win32VersionValue',            0 ],
	  [ 'uint32v', 'SizeOfImage',                  0 ],
	  [ 'uint32v', 'SizeOfHeaders',                0 ],
	  [ 'uint32v', 'CheckSum',                     0 ],
	  [ 'uint16v', 'Subsystem',                    0 ],
	  [ 'uint16v', 'DllCharacteristics',           0 ],
	  [ 'uint32v', 'SizeOfStackReserve',           0 ],
	  [ 'uint32v', 'SizeOfStackCommit',            0 ],
	  [ 'uint32v', 'SizeOfHeapReserve',            0 ],
	  [ 'uint32v', 'SizeOfHeapCommit',             0 ],
	  [ 'uint32v', 'LoaderFlags',                  0 ],
	  [ 'uint32v', 'NumberOfRvaAndSizes',          0 ],
	  [ 'template', 'DataDirectory', Rex::Struct2::CStructTemplate.new(
	    [ 'template', 'DataDirectoryEntry_0', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_1', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_2', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_3', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_4', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_5', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_6', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_7', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_8', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_9', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_10', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_11', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_12', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_13', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_14', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_15', IMAGE_DATA_DIRECTORY ]
	  )]
	)

	# #define IMAGE_SIZEOF_NT_OPTIONAL64_HEADER    240
	IMAGE_NT_OPTIONAL_HDR64_MAGIC     = 0x20b
	# #define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
	IMAGE_SIZEOF_NT_OPTIONAL64_HEADER = 240

	# Struct
	#   typedef struct _IMAGE_OPTIONAL_HEADER64 {
	#      USHORT      Magic;
	#      UCHAR       MajorLinkerVersion;
	#      UCHAR       MinorLinkerVersion;
	#      ULONG       SizeOfCode;
	#      ULONG       SizeOfInitializedData;
	#      ULONG       SizeOfUninitializedData;
	#      ULONG       AddressOfEntryPoint;
	#      ULONG       BaseOfCode;
	#      ULONGLONG   ImageBase;
	#      ULONG       SectionAlignment;
	#      ULONG       FileAlignment;
	#      USHORT      MajorOperatingSystemVersion;
	#      USHORT      MinorOperatingSystemVersion;
	#      USHORT      MajorImageVersion;
	#      USHORT      MinorImageVersion;
	#      USHORT      MajorSubsystemVersion;
	#      USHORT      MinorSubsystemVersion;
	#      ULONG       Win32VersionValue;
	#      ULONG       SizeOfImage;
	#      ULONG       SizeOfHeaders;
	#      ULONG       CheckSum;
	#      USHORT      Subsystem;
	#      USHORT      DllCharacteristics;
	#      ULONGLONG   SizeOfStackReserve;
	#      ULONGLONG   SizeOfStackCommit;
	#      ULONGLONG   SizeOfHeapReserve;
	#      ULONGLONG   SizeOfHeapCommit;
	#      ULONG       LoaderFlags;
	#      ULONG       NumberOfRvaAndSizes;
	#      IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	#   } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
	IMAGE_OPTIONAL_HEADER64 = Rex::Struct2::CStructTemplate.new(
	  [ 'uint16v', 'Magic',                        0 ],
	  [ 'uint8',   'MajorLinkerVersion',           0 ],
	  [ 'uint8',   'MinorLinkerVersion',           0 ],
	  [ 'uint32v', 'SizeOfCode',                   0 ],
	  [ 'uint32v', 'SizeOfInitializeData',         0 ],
	  [ 'uint32v', 'SizeOfUninitializeData',       0 ],
	  [ 'uint32v', 'AddressOfEntryPoint',          0 ],
	  [ 'uint32v', 'BaseOfCode',                   0 ],
	  [ 'uint64v', 'ImageBase',                    0 ],
	  [ 'uint32v', 'SectionAlignment',             0 ],
	  [ 'uint32v', 'FileAlignment',                0 ],
	  [ 'uint16v', 'MajorOperatingsystemVersion',  0 ],
	  [ 'uint16v', 'MinorOperatingsystemVersion',  0 ],
	  [ 'uint16v', 'MajorImageVersion',            0 ],
	  [ 'uint16v', 'MinorImageVersion',            0 ],
	  [ 'uint16v', 'MajorSubsystemVersion',        0 ],
	  [ 'uint16v', 'MinorSubsystemVersion',        0 ],
	  [ 'uint32v', 'Win32VersionValue',            0 ],
	  [ 'uint32v', 'SizeOfImage',                  0 ],
	  [ 'uint32v', 'SizeOfHeaders',                0 ],
	  [ 'uint32v', 'CheckSum',                     0 ],
	  [ 'uint16v', 'Subsystem',                    0 ],
	  [ 'uint16v', 'DllCharacteristics',           0 ],
	  [ 'uint64v', 'SizeOfStackReserve',           0 ],
	  [ 'uint64v', 'SizeOfStackCommit',            0 ],
	  [ 'uint64v', 'SizeOfHeapReserve',            0 ],
	  [ 'uint64v', 'SizeOfHeapCommit',             0 ],
	  [ 'uint32v', 'LoaderFlags',                  0 ],
	  [ 'uint32v', 'NumberOfRvaAndSizes',          0 ],
	  [ 'template', 'DataDirectory', Rex::Struct2::CStructTemplate.new(
	    [ 'template', 'DataDirectoryEntry_0', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_1', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_2', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_3', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_4', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_5', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_6', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_7', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_8', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_9', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_10', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_11', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_12', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_13', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_14', IMAGE_DATA_DIRECTORY ],
	    [ 'template', 'DataDirectoryEntry_15', IMAGE_DATA_DIRECTORY ]
	  )]
	)

	class OptionalHeader < GenericHeader
		def ImageBase
			v['ImageBase']
		end
		def FileAlignment
			v['FileAlignment']
		end
	end

	class OptionalHeader32 < OptionalHeader
		def initialize(rawdata)
			optional_header = IMAGE_OPTIONAL_HEADER32.make_struct

			if !optional_header.from_s(rawdata)
				raise OptionalHeaderError, "Couldn't parse IMAGE_OPTIONAL_HEADER32", caller
			end

			if optional_header.v['Magic'] != IMAGE_NT_OPTIONAL_HDR32_MAGIC
				raise OptionalHeaderError, "Magic did not match!", caller()
			end

			self.struct = optional_header
		end
	end

	class OptionalHeader64 < OptionalHeader
		def initialize(rawdata)
			optional_header = IMAGE_OPTIONAL_HEADER64.make_struct

			if !optional_header.from_s(rawdata)
				raise OptionalHeaderError, "Couldn't parse IMAGE_OPTIONAL_HEADER64", caller
			end

			if optional_header.v['Magic'] != IMAGE_NT_OPTIONAL_HDR64_MAGIC
				raise OptionalHeaderError, "Magic did not match!", caller()
			end

			self.struct = optional_header
		end
	end

	def self._parse_optional_header(rawdata)
		case rawdata.length
			# no optional header
			when 0
				return nil

			# good, good
			when IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
				return OptionalHeader32.new(rawdata)

			when IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
				return OptionalHeader64.new(rawdata)

			# bad, bad
			else
				raise OptionalHeaderError, "I don't know this header size, #{rawdata.length}", caller
		end

	end

	# #define IMAGE_SIZEOF_SECTION_HEADER          40
	IMAGE_SIZEOF_SECTION_HEADER = 40
	# Struct
	#   typedef struct _IMAGE_SECTION_HEADER {
	#       BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	#       union {
	#               DWORD   PhysicalAddress;
	#               DWORD   VirtualSize;
	#       } Misc;
	#       DWORD   VirtualAddress;
	#       DWORD   SizeOfRawData;
	#       DWORD   PointerToRawData;
	#       DWORD   PointerToRelocations;
	#       DWORD   PointerToLinenumbers;
	#       WORD    NumberOfRelocations;
	#       WORD    NumberOfLinenumbers;
	#       DWORD   Characteristics;
	#   } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
	IMAGE_SECTION_HEADER = Rex::Struct2::CStructTemplate.new(
	  [ 'string',  'Name', 8,               '' ],
	  [ 'uint32v', 'Misc',                   0 ],
	  [ 'uint32v', 'VirtualAddress',         0 ],
	  [ 'uint32v', 'SizeOfRawData',          0 ],
	  [ 'uint32v', 'PointerToRawData',       0 ],
	  [ 'uint32v', 'PointerToRelocations',   0 ],
	  [ 'uint32v', 'NumberOfRelocations',    0 ],
	  [ 'uint32v', 'NumberOfLineNumbers',    0 ],
	  [ 'uint32v', 'Characteristics',        0 ]
	)

	class SectionHeader < GenericHeader
		def initialize(rawdata)
			section_header = IMAGE_SECTION_HEADER.make_struct

			if !section_header.from_s(rawdata)
				raise SectionHeaderError, "Could not parse header", caller
			end

			self.struct = section_header
		end

		def VirtualAddress
			v['VirtualAddress']
		end
		def SizeOfRawData
			v['SizeOfRawData']
		end
		def PointerToRawData
			v['PointerToRawData']
		end
	end

	def self._parse_section_headers(rawdata)
		section_headers = [ ]
		size = IMAGE_SIZEOF_SECTION_HEADER
		numsections = rawdata.length / size

		numsections.times do |i|
			data = rawdata[i * size, size]
			section_headers << SectionHeader.new(data)
		end

		return section_headers
	end

	# #define IMAGE_SIZEOF_BASE_RELOCATION         8
	IMAGE_SIZEOF_BASE_RELOCATION = 8

	# Struct
	#   typedef struct _IMAGE_BASE_RELOCATION {
	#       DWORD   VirtualAddress;
	#       DWORD   SizeOfBlock;
	#   //  WORD    TypeOffset[1];
	#   } IMAGE_BASE_RELOCATION;
	#   typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
	IMAGE_BASE_RELOCATION = Rex::Struct2::CStructTemplate.new(
	  [ 'uint32v', 'VirtualAddress',         0 ],
	  [ 'uint32v', 'SizeOfBlock',            0 ]
	)
	IMAGE_BASE_RELOCATION_TYPE_OFFSET = Rex::Struct2::CStructTemplate.new(
	  [ 'uint16v', 'TypeOffset',             0 ]
	)

	class RelocationDirectory
		attr_accessor :entries, :rva

		def initialize(rva, entries)
			self.rva     = rva
			self.entries = entries
			self.name    = name
			self.characteristics = chars
			self.timedate = timedate
			self.version = version
			self.entries = []
		end
	end

	class RelocationEntry
		attr_accessor :rva, :reltype

		def initialize(_rva, _type)
			self.rva     = _rva
			self.reltype = _type
		end
	end


	class ResourceDirectory
		attr_accessor :entries, :name

		def initialize(name, entries)
			self.name   = name
			self.entries = entries
		end
	end

	class ResourceEntry
		attr_accessor :path, :lang, :code, :rva, :size, :pe, :file

		def initialize(pe, path, lang, code, rva, size, file)
			self.pe    = pe
			self.path  = path
			self.lang  = lang
			self.code  = code
			self.rva   = rva
			self.size  = size
			self.file  = file.to_s
		end

		def data
			pe._isource.read(pe.rva_to_file_offset(rva), size)
		end
	end

	# Struct
	#   typedef struct {
	#       DWORD   Size;
	#       DWORD   TimeDateStamp;
	#       WORD    MajorVersion;
	#       WORD    MinorVersion;
	#       DWORD   GlobalFlagsClear;
	#       DWORD   GlobalFlagsSet;
	#       DWORD   CriticalSectionDefaultTimeout;
	#       DWORD   DeCommitFreeBlockThreshold;
	#       DWORD   DeCommitTotalFreeThreshold;
	#       DWORD   LockPrefixTable;            // VA
	#       DWORD   MaximumAllocationSize;
	#       DWORD   VirtualMemoryThreshold;
	#       DWORD   ProcessHeapFlags;
	#       DWORD   ProcessAffinityMask;
	#       WORD    CSDVersion;
	#       WORD    Reserved1;
	#       DWORD   EditList;                   // VA
	#       DWORD   SecurityCookie;             // VA
	#       DWORD   SEHandlerTable;             // VA
	#       DWORD   SEHandlerCount;
	#   } IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;
	#
	IMAGE_LOAD_CONFIG_DIRECTORY32 = Rex::Struct2::CStructTemplate.new(
	  [ 'uint32v', 'Size',                          0 ],
	  [ 'uint32v', 'TimeDateStamp',                 0 ],
	  [ 'uint16v', 'MajorVersion',                  0 ],
	  [ 'uint16v', 'MinorVersion',                  0 ],
	  [ 'uint32v', 'GlobalFlagsClear',              0 ],
	  [ 'uint32v', 'GlobalFlagsSet',                0 ],
	  [ 'uint32v', 'CriticalSectionDefaultTimeout', 0 ],
	  [ 'uint32v', 'DeCommitFreeBlockThreshold',    0 ],
	  [ 'uint32v', 'DeCommitTotalFreeThreshold',    0 ],
	  [ 'uint32v', 'LockPrefixTable',               0 ],
	  [ 'uint32v', 'MaximumAllocationSize',         0 ],
	  [ 'uint32v', 'VirtualMemoryThreshold',        0 ],
	  [ 'uint32v', 'ProcessHeapFlags',              0 ],
	  [ 'uint32v', 'ProcessAffinityMask',           0 ],
	  [ 'uint16v', 'CSDVersion',                    0 ],
	  [ 'uint16v', 'Reserved1',                     0 ],
	  [ 'uint32v', 'EditList',                      0 ],
	  [ 'uint32v', 'SecurityCookie',                0 ],
	  [ 'uint32v', 'SEHandlerTable',                0 ],
	  [ 'uint32v', 'SEHandlerCount',                0 ]
	)

	# Struct
	#   typedef struct {
	#       ULONG      Size;
	#       ULONG      TimeDateStamp;
	#       USHORT     MajorVersion;
	#       USHORT     MinorVersion;
	#       ULONG      GlobalFlagsClear;
	#       ULONG      GlobalFlagsSet;
	#       ULONG      CriticalSectionDefaultTimeout;
	#       ULONGLONG  DeCommitFreeBlockThreshold;
	#       ULONGLONG  DeCommitTotalFreeThreshold;
	#       ULONGLONG  LockPrefixTable;         // VA
	#       ULONGLONG  MaximumAllocationSize;
	#       ULONGLONG  VirtualMemoryThreshold;
	#       ULONGLONG  ProcessAffinityMask;
	#       ULONG      ProcessHeapFlags;
	#       USHORT     CSDVersion;
	#       USHORT     Reserved1;
	#       ULONGLONG  EditList;                // VA
	#       ULONGLONG  SecurityCookie;          // VA
	#       ULONGLONG  SEHandlerTable;          // VA
	#       ULONGLONG  SEHandlerCount;
	#   } IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;
	IMAGE_LOAD_CONFIG_DIRECTORY64 = Rex::Struct2::CStructTemplate.new(
	  [ 'uint32v', 'Size',                          0 ],
	  [ 'uint32v', 'TimeDateStamp',                 0 ],
	  [ 'uint16v', 'MajorVersion',                  0 ],
	  [ 'uint16v', 'MinorVersion',                  0 ],
	  [ 'uint32v', 'GlobalFlagsClear',              0 ],
	  [ 'uint32v', 'GlobalFlagsSet',                0 ],
	  [ 'uint32v', 'CriticalSectionDefaultTimeout', 0 ],
	  [ 'uint64v', 'DeCommitFreeBlockThreshold',    0 ],
	  [ 'uint64v', 'DeCommitTotalFreeThreshold',    0 ],
	  [ 'uint64v', 'LockPrefixTable',               0 ],
	  [ 'uint64v', 'MaximumAllocationSize',         0 ],
	  [ 'uint64v', 'VirtualMemoryThreshold',        0 ],
	  [ 'uint64v', 'ProcessAffinityMask',           0 ],
	  [ 'uint32v', 'ProcessHeapFlags',              0 ],
	  [ 'uint16v', 'CSDVersion',                    0 ],
	  [ 'uint16v', 'Reserved1',                     0 ],
	  [ 'uint64v', 'EditList',                      0 ],
	  [ 'uint64v', 'SecurityCookie',                0 ],
	  [ 'uint64v', 'SEHandlerTable',                0 ],
	  [ 'uint64v', 'SEHandlerCount',                0 ]
	)


	class ConfigHeader < GenericHeader

	end

	#--
	# doesn't seem to be used -- not compatible with 64-bit
	#def self._parse_config_header(rawdata)
	#	header = IMAGE_LOAD_CONFIG_DIRECTORY32.make_struct
	#	header.from_s(rawdata)
	#	ConfigHeader.new(header)
	#end
	#++

	def _parse_config_header

		#
		# Get the data directory entry, size, etc
		#
		exports_entry = _optional_header['DataDirectory'][IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
		rva           = exports_entry.v['VirtualAddress']
		size          = exports_entry.v['Size']

		return nil if size == 0

		#
		# Ok, so we have the data directory, now lets parse it
		#

		dirdata = _isource.read(rva_to_file_offset(rva), size)
		klass   = (ptr_64?) ? IMAGE_LOAD_CONFIG_DIRECTORY64 : IMAGE_LOAD_CONFIG_DIRECTORY32
		header  = klass.make_struct

		header.from_s(dirdata)

		@config = ConfigHeader.new(header)
	end


	def config
		_parse_config_header if @config.nil?
		@config
	end

	#
	# TLS Directory
	#

	# Struct
	#   typedef struct {
	#       DWORD   Size;
	#       DWORD   TimeDateStamp;
	#       WORD    MajorVersion;
	#       WORD    MinorVersion;
	#       DWORD   GlobalFlagsClear;
	#       DWORD   GlobalFlagsSet;
	#       DWORD   CriticalSectionDefaultTimeout;
	#       DWORD   DeCommitFreeBlockThreshold;
	#       DWORD   DeCommitTotalFreeThreshold;
	#       DWORD   LockPrefixTable;            // VA
	#       DWORD   MaximumAllocationSize;
	#       DWORD   VirtualMemoryThreshold;
	#       DWORD   ProcessHeapFlags;
	#       DWORD   ProcessAffinityMask;
	#       WORD    CSDVersion;
	#       WORD    Reserved1;
	#       DWORD   EditList;                   // VA
	#       DWORD   SecurityCookie;             // VA
	#       DWORD   SEHandlerTable;             // VA
	#       DWORD   SEHandlerCount;
	#   } IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;
	IMAGE_LOAD_TLS_DIRECTORY32 = Rex::Struct2::CStructTemplate.new(
	  [ 'uint32v', 'Size',                          0 ],
	  [ 'uint32v', 'TimeDateStamp',                 0 ],
	  [ 'uint16v', 'MajorVersion',                  0 ],
	  [ 'uint16v', 'MinorVersion',                  0 ],
	  [ 'uint32v', 'GlobalFlagsClear',              0 ],
	  [ 'uint32v', 'GlobalFlagsSet',                0 ],
	  [ 'uint32v', 'CriticalSectionDefaultTimeout', 0 ],
	  [ 'uint32v', 'DeCommitFreeBlockThreshold',    0 ],
	  [ 'uint32v', 'DeCommitTotalFreeThreshold',    0 ],
	  [ 'uint32v', 'LockPrefixTable',               0 ],
	  [ 'uint32v', 'MaximumAllocationSize',         0 ],
	  [ 'uint32v', 'VirtualMemoryThreshold',        0 ],
	  [ 'uint32v', 'ProcessHeapFlags',              0 ],
	  [ 'uint32v', 'ProcessAffinityMask',           0 ],
	  [ 'uint16v', 'CSDVersion',                    0 ],
	  [ 'uint16v', 'Reserved1',                     0 ],
	  [ 'uint32v', 'EditList',                      0 ],
	  [ 'uint32v', 'SecurityCookie',                0 ],
	  [ 'uint32v', 'SEHandlerTable',                0 ],
	  [ 'uint32v', 'SEHandlerCount',                0 ]
	)

	# Struct
	#   typedef struct {
	#       ULONG      Size;
	#       ULONG      TimeDateStamp;
	#       USHORT     MajorVersion;
	#       USHORT     MinorVersion;
	#       ULONG      GlobalFlagsClear;
	#       ULONG      GlobalFlagsSet;
	#       ULONG      CriticalSectionDefaultTimeout;
	#       ULONGLONG  DeCommitFreeBlockThreshold;
	#       ULONGLONG  DeCommitTotalFreeThreshold;
	#       ULONGLONG  LockPrefixTable;         // VA
	#       ULONGLONG  MaximumAllocationSize;
	#       ULONGLONG  VirtualMemoryThreshold;
	#       ULONGLONG  ProcessAffinityMask;
	#       ULONG      ProcessHeapFlags;
	#       USHORT     CSDVersion;
	#       USHORT     Reserved1;
	#       ULONGLONG  EditList;                // VA
	#       ULONGLONG  SecurityCookie;          // VA
	#       ULONGLONG  SEHandlerTable;          // VA
	#       ULONGLONG  SEHandlerCount;
	#   } IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;
	IMAGE_LOAD_TLS_DIRECTORY64 = Rex::Struct2::CStructTemplate.new(
	  [ 'uint32v', 'Size',                          0 ],
	  [ 'uint32v', 'TimeDateStamp',                 0 ],
	  [ 'uint16v', 'MajorVersion',                  0 ],
	  [ 'uint16v', 'MinorVersion',                  0 ],
	  [ 'uint32v', 'GlobalFlagsClear',              0 ],
	  [ 'uint32v', 'GlobalFlagsSet',                0 ],
	  [ 'uint32v', 'CriticalSectionDefaultTimeout', 0 ],
	  [ 'uint64v', 'DeCommitFreeBlockThreshold',    0 ],
	  [ 'uint64v', 'DeCommitTotalFreeThreshold',    0 ],
	  [ 'uint64v', 'LockPrefixTable',               0 ],
	  [ 'uint64v', 'MaximumAllocationSize',         0 ],
	  [ 'uint64v', 'VirtualMemoryThreshold',        0 ],
	  [ 'uint64v', 'ProcessAffinityMask',           0 ],
	  [ 'uint32v', 'ProcessHeapFlags',              0 ],
	  [ 'uint16v', 'CSDVersion',                    0 ],
	  [ 'uint16v', 'Reserved1',                     0 ],
	  [ 'uint64v', 'EditList',                      0 ],
	  [ 'uint64v', 'SecurityCookie',                0 ],
	  [ 'uint64v', 'SEHandlerTable',                0 ],
	  [ 'uint64v', 'SEHandlerCount',                0 ]
	)


	class TLSHeader < GenericHeader

	end

	def _parse_tls_header

		#
		# Get the data directory entry, size, etc
		#
		exports_entry = _optional_header['DataDirectory'][IMAGE_DIRECTORY_ENTRY_TLS]
		rva           = exports_entry.v['VirtualAddress']
		size          = exports_entry.v['Size']

		return nil if size == 0

		#
		# Ok, so we have the data directory, now lets parse it
		#

		dirdata = _isource.read(rva_to_file_offset(rva), size)
		klass   = (ptr_64?) ? IMAGE_LOAD_TLS_DIRECTORY64 : IMAGE_LOAD_TLS_DIRECTORY32
		header  = klass.make_struct

		header.from_s(dirdata)

		@tls = TLSHeader.new(header)
	end


	def tls
		_parse_config_header if @tls.nil?
		@tls
	end

	##
	#
	# Exception directory
	#
	##

	IMAGE_RUNTIME_FUNCTION_ENTRY_SZ = 12
	# Struct
	#   typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
	#       DWORD BeginAddress;
	#       DWORD EndAddress;
	#       DWORD UnwindInfoAddress;
	#   } _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;
	IMAGE_RUNTIME_FUNCTION_ENTRY = Rex::Struct2::CStructTemplate.new(
	  [ 'uint32v', 'BeginAddress',                  0 ],
	  [ 'uint32v', 'EndAddress',                    0 ],
	  [ 'uint32v', 'UnwindInfoAddress',             0 ]
	)

	UNWIND_INFO_HEADER_SZ = 4
	UNWIND_INFO_HEADER = Rex::Struct2::CStructTemplate.new(
	  [ 'uint8', 'VersionFlags',                  0 ],
	  [ 'uint8', 'SizeOfProlog',                  0 ],
	  [ 'uint8', 'CountOfCodes',                  0 ],
	  [ 'uint8', 'FrameRegisterAndOffset',        0 ]
	)

	UWOP_PUSH_NONVOL     = 0  # 1 node
	UWOP_ALLOC_LARGE     = 1  # 2 or 3 nodes
	UWOP_ALLOC_SMALL     = 2  # 1 node
	UWOP_SET_FPREG       = 3  # 1 node
	UWOP_SAVE_NONVOL     = 4  # 2 nodes
	UWOP_SAVE_NONVOL_FAR = 5  # 3 nodes
	UWOP_SAVE_XMM128     = 8  # 2 nodes
	UWOP_SAVE_XMM128_FAR = 9  # 3 nodes
	UWOP_PUSH_MACHFRAME  = 10 # 1 node

	UNW_FLAG_EHANDLER  = 1
	UNW_FLAG_UHANDLER  = 2
	UNW_FLAG_CHAININFO = 4

	class UnwindCode
		def initialize(data)

			self.code_offset  = data[0].to_i
			self.unwind_op    = data[1].to_i & 0xf
			self.op_info      = data[1].to_i >> 4
			self.frame_offset = data[2..3].unpack("v")[0]

			data.slice!(0, 4)
		end

		attr_reader :code_offset, :unwind_op, :op_info, :frame_offset
		attr_writer :code_offset, :unwind_op, :op_info, :frame_offset

	end

	class UnwindInfo
		def initialize(pe, unwind_rva)
			data = pe.read_rva(unwind_rva, UNWIND_INFO_HEADER_SZ)

			unwind  = UNWIND_INFO_HEADER.make_struct
			unwind.from_s(data)

			@version               = unwind.v['VersionFlags'] & 0x7
			@flags                 = unwind.v['VersionFlags'] >> 3
			@size_of_prolog        = unwind.v['SizeOfProlog']
			@count_of_codes        = unwind.v['CountOfCodes']
			@frame_register        = unwind.v['FrameRegisterAndOffset'] & 0xf
			@frame_register_offset = unwind.v['FrameRegisterAndOffset'] >> 4

			# Parse unwind codes
			clist = pe.read_rva(unwind_rva + UNWIND_INFO_HEADER_SZ, count_of_codes * 4)

			@unwind_codes = []

			while clist.length > 0
				@unwind_codes << UnwindCode.new(clist)
			end
		end

		attr_reader :version, :flags, :size_of_prolog, :count_of_codes
		attr_reader :frame_register, :frame_register_offset

		def unwind_codes
			@unwind_codes
		end

	end

	class RuntimeFunctionEntry

		def initialize(pe, data)
			@pe = pe
			@begin_address, @end_address, @unwind_info_address = data.unpack("VVV");
			self.unwind_info = UnwindInfo.new(pe, unwind_info_address)
		end

		attr_reader :begin_address, :end_address, :unwind_info_address
		attr_reader :unwind_info
		attr_writer :unwind_info

	end

	def _load_exception_directory
		@exception   = []

		exception_entry = _optional_header['DataDirectory'][IMAGE_DIRECTORY_ENTRY_EXCEPTION]
		rva             = exception_entry.v['VirtualAddress']
		size            = exception_entry.v['Size']

		return if (rva == 0)

		data = _isource.read(rva_to_file_offset(rva), size)

		case hdr.file.Machine
			when IMAGE_FILE_MACHINE_AMD64
				count = data.length / IMAGE_RUNTIME_FUNCTION_ENTRY_SZ

				count.times { |current|
					@exception << RuntimeFunctionEntry.new(self,
						data.slice!(0, IMAGE_RUNTIME_FUNCTION_ENTRY_SZ))
				}
			else
		end

		return @exception
	end


	def exception
		_load_exception_directory if @exception.nil?
		@exception
	end

	#
	# Just a stupid routine to round an offset up to it's alignment.
	#
	# For example, you're going to want this for FileAlignment and
	# SectionAlignment, etc...
	#
	def self._align_offset(offset, alignment)
		offset += alignment - 1
		offset -= offset % alignment
		return offset
	end

	#
	# instance stuff
	#

	attr_accessor :_isource
	attr_accessor :_dos_header, :_file_header, :_optional_header,
	              :_section_headers, :_config_header, :_tls_header, :_exception_header

	attr_accessor :sections, :header_section, :image_base

	attr_accessor :_imports_cache, :_imports_cached
	attr_accessor :_exports_cache, :_exports_cached
	attr_accessor :_relocations_cache, :_relocations_cached
	attr_accessor :_resources_cache, :_resources_cached

	attr_accessor :hdr

	def self.new_from_file(filename, disk_backed = false)

		file = ::File.new(filename)
		file.binmode # windows... :\

		if disk_backed
			return self.new(ImageSource::Disk.new(file))
		else
			obj = new_from_string(file.read)
			file.close
			return obj
		end
	end

	def self.new_from_string(data)
		return self.new(ImageSource::Memory.new(data))
	end

	def close
		_isource.close
	end

	#
	#
	# Random rva, vma, file offset, section offset, etc
	# conversion routines...
	#
	#
	def rva_to_vma(rva)
		return rva + image_base
	end

	def vma_to_rva(vma)
		return vma - image_base
	end

	def rva_to_file_offset(rva)
		all_sections.each do |section|
			if section.contains_rva?(rva)
				return section.rva_to_file_offset(rva)
			end
		end
		raise WtfError, "wtf!", caller
	end

	def vma_to_file_offset(vma)
		return rva_to_file_offset(vma_to_rva(vma))
	end

	def file_offset_to_rva(foffset)
		if foffset < 0
			raise WtfError, "lame", caller
		end

		all_sections.each do |section|
			if section.contains_file_offset?(foffset)
				return section.file_offset_to_rva(foffset)
			end
		end

		raise WtfError, "wtf! #{foffset}", caller
	end

	def file_offset_to_vma(foffset)
		return rva_to_vma(file_offset_to_rva(foffset))
	end

	#
	#
	# Some routines to find which section something belongs
	# to.  These will search all_sections (so including
	# our fake header section, etc...
	#
	#

	#
	# Find a section by an RVA
	#
	def _find_section_by_rva(rva)
		all_sections.each do |section|
			if section.contains_rva?(rva)
				return section
			end
		end

		return nil
	end
	def find_section_by_rva(rva)
		section = _find_section_by_rva(rva)

		if !section
			raise WtfError, "Cannot find rva! #{rva}", caller
		end

		return section
	end

	#
	# Find a section by a VMA
	#
	def find_section_by_vma(vma)
		return find_section_by_rva(vma_to_rva(vma))
	end

	def valid_rva?(rva)
		_find_section_by_rva(rva) != nil
	end
	def valid_vma?(vma)
		_find_section_by_rva(vma_to_rva(vma)) != nil
	end

	#
	#
	# Some convenient methods to read a vma/rva without having
	# the section... (inefficent though I suppose...)
	#
	#

	def read_rva(rva, length)
		return find_section_by_rva(rva).read_rva(rva, length)
	end

	def read_vma(vma, length)
		return read_rva(vma_to_rva(vma), length)
	end

	def read_asciiz_rva(rva)
		return find_section_by_rva(rva).read_asciiz_rva(rva)
	end

	def read_asciiz_vma(vma)
		return read_asciiz_rva(vma_to_rva(vma))
	end

	#
	#
	# Imports, exports, and other stuff!
	#
	#

	#
	# We lazily parse the imports, and then cache it
	#
	def imports
		if !_imports_cached
			self._imports_cache  = _load_imports
			self._imports_cached = true
		end
		return _imports_cache
	end

	def _load_imports
		#
		# Get the data directory entry, size, etc
		#
		imports_entry = _optional_header['DataDirectory'][1]
		rva           = imports_entry.v['VirtualAddress']
		size          = imports_entry.v['Size']

		return nil if size == 0

		#
		# Ok, so we have the data directory, now lets parse it
		#

		imports = [ ]

		descriptors_data = _isource.read(rva_to_file_offset(rva), size)

		while descriptors_data.length >= IMAGE_IMPORT_DESCRIPTOR_SIZE
			descriptor = IMAGE_IMPORT_DESCRIPTOR.make_struct
			descriptor.from_s(descriptors_data)
			descriptors_data = descriptor.leftover

			othunk = descriptor.v['OriginalFirstThunk']
			fthunk = descriptor.v['FirstThunk']

			break if fthunk == 0

			dllname = _isource.read_asciiz(rva_to_file_offset(descriptor.v['Name']))

			import = ImportDescriptor.new(dllname, [ ])

			# we prefer the Characteristics/OriginalFirstThunk...
			thunk_off = rva_to_file_offset(othunk == 0 ? fthunk : othunk)

			while (orgrva = _isource.read(thunk_off, 4).unpack('V')[0]) != 0
				hint = nil
				name = nil

				if (orgrva & IMAGE_ORDINAL_FLAG32) != 0
					hint = orgrva & 0xffff
				else
					foff = rva_to_file_offset(orgrva)
					hint = _isource.read(foff, 2).unpack('v')[0]
					name = _isource.read_asciiz(foff + 2)
				end

				import.entries << ImportEntry.new(name, hint)

				thunk_off += 4
			end

			imports << import
		end

		return imports
	end



	#
	# We lazily parse the exports, and then cache it
	#
	def exports
		if !_exports_cached
			self._exports_cache  = _load_exports
			self._exports_cached = true
		end
		return _exports_cache
	end

	def _load_exports

		#
		# Get the data directory entry, size, etc
		#
		exports_entry = _optional_header['DataDirectory'][0]
		rva           = exports_entry.v['VirtualAddress']
		size          = exports_entry.v['Size']

		return nil if size == 0

		#
		# Ok, so we have the data directory, now lets parse it
		#

		directory = IMAGE_EXPORT_DESCRIPTOR.make_struct
		directory.from_s(_isource.read(rva_to_file_offset(rva), IMAGE_EXPORT_DESCRIPTOR_SIZE))

		#
		# We can have nameless exports, so we need to do the whole
		# NumberOfFunctions NumberOfNames foo
		#
		num_functions = directory.v['NumberOfFunctions']
		num_names     = directory.v['NumberOfNames']

		dllname_rva   = directory.v['Name']
		dllname       = _isource.read_asciiz(rva_to_file_offset(dllname_rva))

		# FIXME Base, etc
		fun_off       = rva_to_file_offset(directory.v['AddressOfFunctions'])
		name_off      = rva_to_file_offset(directory.v['AddressOfNames'])
		ord_off       = rva_to_file_offset(directory.v['AddressOfNameOrdinals'])
		base          = directory.v['Base']

		# Allocate the list of names
		names = Array.new(num_functions)

		#
		# Iterate the names and name/ordinal list, getting the names
		# and storing them in the name list...
		#
		num_names.times do |i|
			name_rva = _isource.read(name_off + (i * 4), 4).unpack('V')[0]
			ordinal  = _isource.read(ord_off + (i * 2), 2).unpack('v')[0]
			name     = _isource.read_asciiz(rva_to_file_offset(name_rva))

			# store the exported name in the name list
			names[ordinal] = name
		end

		exports = ExportDirectory.new(dllname, [ ], base)

		#
		# Now just iterate the functions (rvas) list..
		#
		num_functions.times do |i|
			rva      = _isource.read(fun_off + (i * 4), 4).unpack('V')[0]

			# ExportEntry.new(name, ordinal, rva)
			exports.entries << ExportEntry.new(names[i], i + base, rva)
		end

		return exports
	end

	#
	# Base relocations in the hizzy
	#
	def relocations
		if !_relocations_cached
			self._relocations_cache  = _load_relocations
			self._relocations_cached = true
		end
		return _relocations_cache
	end

	def _load_relocations

		#
		# Get the data directory entry, size, etc
		#
		exports_entry = _optional_header['DataDirectory'][5]
		rva           = exports_entry.v['VirtualAddress']
		size          = exports_entry.v['Size']

		return nil if size == 0

		#
		# Ok, so we have the data directory, now lets parse it
		#

		dirdata = _isource.read(rva_to_file_offset(rva), size)

		relocdirs = [ ]

		while dirdata.length >= IMAGE_SIZEOF_BASE_RELOCATION
			header = IMAGE_BASE_RELOCATION.make_struct
			header.from_s(dirdata)
			dirdata = header.leftover

			numrelocs = (header.v['SizeOfBlock'] - IMAGE_SIZEOF_BASE_RELOCATION) / 2

			relocbase = header.v['VirtualAddress']

			relocdir = RelocationDirectory.new(relocbase, [ ])

			numrelocs.times do
				reloc = IMAGE_BASE_RELOCATION_TYPE_OFFSET.make_struct
				reloc.from_s(dirdata)
				dirdata = reloc.leftover

				typeoffset = reloc.v['TypeOffset']

				relocrva  = relocbase + (typeoffset & 0xfff)
				reloctype = (typeoffset >> 12) & 0xf

				relocdir.entries << RelocationEntry.new(relocrva, reloctype)
			end

			relocdirs << relocdir
		end

		return relocdirs
	end


	#
	# We lazily parse the resources, and then cache them
	#
	def resources
		if !_resources_cached
			_load_resources
			self._resources_cached = true
		end

		return self._resources_cache
	end

	def _load_resources
		#
		# Get the data directory entry, size, etc
		#
		rsrc_entry = _optional_header['DataDirectory'][IMAGE_DIRECTORY_ENTRY_RESOURCE]
		rva        = rsrc_entry.v['VirtualAddress']
		size       = rsrc_entry.v['Size']

		return nil if size == 0

		#
		# Ok, so we have the data directory, now lets parse it
		#
		data = _isource.read(rva_to_file_offset(rva), size)

		self._resources_cache = {}
		_parse_resource_directory(data)
	end

	def _parse_resource_directory(data, rname=0, rvalue=0x80000000, path='0', pname=nil)

		pname = _parse_resource_name(data, rname)
		if (path.scan('/').length == 1)
			if (pname !~ /^\d+/)
				path = "/" + pname
			else
				path = "/" + _resource_lookup( (rname & ~0x80000000).to_s)
			end
		end


		rvalue &= ~0x80000000
		vals  = data[rvalue, 16].unpack('VVvvvv')

		chars = vals[0]
		tdate = vals[1]
		vers  = "#{vals[2]}#{vals[3]}"
		count = vals[4] + vals[5]

		0.upto(count-1) do |i|

			ename, evalue = data[rvalue + 16 + ( i * 8), 8].unpack('VV')
			epath = path + '/' + i.to_s

			if (ename & 0x80000000 != 0)
				pname = _parse_resource_name(data, ename)
			end

			if (evalue & 0x80000000 != 0)
				# This is a subdirectory
				_parse_resource_directory(data, ename, evalue, epath, pname)
			else
				# This is an entry
				_parse_resource_entry(data, ename, evalue, epath, pname)
			end
		end

	end

	def _resource_lookup(i)
		tbl = {
			'1'      => 'RT_CURSOR',
			'2'      => 'RT_BITMAP',
			'3'      => 'RT_ICON',
			'4'      => 'RT_MENU',
			'5'      => 'RT_DIALOG',
			'6'      => 'RT_STRING',
			'7'      => 'RT_FONTDIR',
			'8'      => 'RT_FONT',
			'9'      => 'RT_ACCELERATORS',
			'10'     => 'RT_RCDATA',
			'11'     => 'RT_MESSAGETABLE',
			'12'     => 'RT_GROUP_CURSOR',
			'14'     => 'RT_GROUP_ICON',
			'16'     => 'RT_VERSION',
			'17'     => 'RT_DLGINCLUDE',
			'19'     => 'RT_PLUGPLAY',
			'20'     => 'RT_VXD',
			'21'     => 'RT_ANICURSOR',
			'22'     => 'RT_ANIICON',
			'23'     => 'RT_HTML',
			'24'     => 'RT_MANIFEST',
			'32767'  => 'RT_ERROR',
			'8192'   => 'RT_NEWRESOURCE',
			'8194'   => 'RT_NEWBITMAP',
			'8196'   => 'RT_NEWMENU',
			'8197'   => 'RT_NEWDIALOG'
		}
		tbl[i] || i
	end

	def _parse_resource_entry(data, rname, rvalue, path, pname)

		rva, size, code = data[rvalue, 12].unpack('VVV')
		lang = _parse_resource_name(data, rname)

		ent = ResourceEntry.new(
			self,
			path,
			lang,
			code,
			rva,
			size,
			pname
		)
		self._resources_cache[path] = ent
	end

	def _parse_resource_name(data, rname)
		if (rname & 0x80000000 != 0)
			rname &= ~0x80000000
			unistr = data[rname+2, 2 * data[rname,2].unpack('v')[0] ]
			unistr, trash = unistr.split(/\x00\x00/, 2)
			return unistr ? unistr.gsub(/\x00/, '') : nil
		end

		rname.to_s
	end

	def update_checksum
		off = _dos_header.e_lfanew + IMAGE_FILE_HEADER_SIZE + 0x40
		_isource.rawdata[off, 4] = [0].pack('V')

		rem = _isource.size % 4
		sum_me = ''
		sum_me << _isource.rawdata
		sum_me << "\x00" * (4 - rem) if rem > 0

		cksum = 0
		sum_me.unpack('V*').each { |el|
			cksum = (cksum & 0xffffffff) + (cksum >> 32) + el
			if cksum > 2**32
				cksum = (cksum & 0xffffffff) + (cksum >> 32)
			end
		}

		cksum = (cksum & 0xffff) + (cksum >> 16)
		cksum += (cksum >> 16)
		cksum &= 0xffff

		cksum += _isource.size

		_isource.rawdata[off, 4] = [cksum].pack('V')
	end

end end end
