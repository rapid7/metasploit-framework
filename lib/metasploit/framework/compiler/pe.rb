# -*- coding: binary -*-

require 'metasm'
require 'metasploit/framework/compiler/utils'
require 'metasploit/framework/compiler/headers/windows'
require 'metasploit/framework/compiler/windows'
require 'rex/peparsey'

module Metasploit
  module Framework
    module Compiler

      class Pe

        FILE_ALIGN = 0x200
        SECT_ALIGN = 0x1000

        MACHINE_AMD64 = 0x8664

        SUBSYSTEM_GUI = 2
        SUBSYSTEM_CUI = 3

        # Section characteristic flags
        SCN_CNT_CODE = 0x00000020
        SCN_CNT_IDATA = 0x00000040
        SCN_MEM_EXEC = 0x20000000
        SCN_MEM_READ = 0x40000000
        SCN_MEM_WRITE = 0x80000000

        TEXT_CHARS = SCN_CNT_CODE | SCN_MEM_EXEC | SCN_MEM_READ
        RDATA_CHARS = SCN_CNT_IDATA | SCN_MEM_READ

        # Standard MSVC DOS stub executable code + message string.
        DOS_STUB_CODE = (
          "\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21" \
          "This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00"
        ).b.freeze

        # Rich header from a real MSVC 2022 (19.36) build.
        # Using a static blob avoids the tricky XOR-checksum derivation for now.
        # Future: generate dynamically via RichHeader.encode(profile, dos_stub_size).
        RICH_HEADER = (
          "\x7E\x13\x87\xAA\x3A\x72\xE9\xF9\x3A\x72\xE9\xF9\x3A\x72\xE9\xF9" \
          "\x33\x0A\x7A\xF9\x30\x72\xE9\xF9\xF1\x1D\xE8\xF8\x38\x72\xE9\xF9" \
          "\xF1\x1D\xEC\xF8\x2B\x72\xE9\xF9\xF1\x1D\xED\xF8\x30\x72\xE9\xF9" \
          "\xF1\x1D\xEA\xF8\x39\x72\xE9\xF9\x61\x1A\xE8\xF8\x3F\x72\xE9\xF9" \
          "\x3A\x72\xE8\xF9\x0A\x72\xE9\xF9\xBC\x02\xE0\xF8\x3B\x72\xE9\xF9" \
          "\xBC\x02\x16\xF9\x3B\x72\xE9\xF9\xBC\x02\xEB\xF8\x3B\x72\xE9\xF9" \
          "\x52\x69\x63\x68\x3A\x72\xE9\xF9"
        ).b.freeze

      #  # Realistic e_lfanew values seen in the wild.
      #  # 0x80 = MSVC default, 0xB8 = some MinGW builds.
      PE_OFFSETS = [0x80, 0xB8].freeze

        def self.from_c(c_source, opts = {})
          new(opts).build_from_c(c_source)
        end

        def initialize(opts = {})
          @subsystem = opts[:subsystem] == :cui ? SUBSYSTEM_CUI : SUBSYSTEM_GUI
          @timestamp = opts[:timestamp] || rand(Time.new(2020, 1, 1).to_i..Time.now.to_i)
          @e_lfanew = opts[:e_lfanew] || PE_OFFSETS.sample
          @rich = opts.fetch(:rich, true)
          @imports = opts[:imports] || {}
          @text_name = opts[:text_name] || ['.text', 'CODE'].sample
          @rdata_name = opts[:rdata_name] || ['.rdata', '.idata'].sample
        end

        def parse_data_directories(raw, offset, count)
          data_directories = []
          count.times do |i|
            rva, sz = raw.byteslice(offset + i * 8, 8).unpack('L< L<')
            data_directories << { rva: rva, size: sz }
          end
          data_directories
        end

        def load_pe(raw)
          dos_header_raw = raw.byteslice(0, 64).unpack('a2 S< S< S< S< S< S< S< S< S< S< S< S< S< a8 S< S< a20 l<')

          keys = %i[
            e_magic e_cblp e_cp e_crlc e_cparhdr e_minalloc e_maxalloc
            e_ss e_sp e_csum e_ip e_cs e_lfarlc e_ovno e_res
            e_oemid e_oeminfo e_res2 e_lfanew
          ]

          @dos_header = keys.zip(dos_header_raw).to_h

          @nt_header_signature = raw.byteslice(@dos_header[:e_lfanew], 4)

          file_header_raw = raw.byteslice(@dos_header[:e_lfanew] + 4, 20).unpack('S< S< L< L< L< S< S<')

          keys = %i[
            Machine NumberOfSections TimeDateStamp PointerToSymbolTable
            NumberOfSymbols SizeOfOptionalHeader Characteristics
          ]

          @file_header = keys.zip(file_header_raw).to_h

          optional_header_offset = @dos_header[:e_lfanew] + 4 + 20

          @optional_header_type = raw.byteslice(optional_header_offset, 2).unpack('S<').first

          ##
          #           OPT_MAGIC_PE32  = 0x10B
          #  OPT_MAGIC_PE32P = 0x20B # PE32+ (64-bit)

          optional_header_raw = raw.byteslice(optional_header_offset, 112).unpack(
            'S< C C L< L< L< L< L< ' \
            'Q< L< L< S< S< S< S< S< S< ' \
            'L< L< L< L< S< S< Q< Q< Q< Q< L< L<'
          )
          keys = %i[
            Magic MajorLinkerVersion MinorLinkerVersion SizeOfCode SizeOfInitializedData
            SizeOfUninitializedData AddressOfEntryPoint BaseOfCode
            ImageBase SectionAlignment FileAlignment
            MajorOperatingSystemVersion MinorOperatingSystemVersion
            MajorImageVersion MinorImageVersion
            MajorSubsystemVersion MinorSubsystemVersion
            Win32VersionValue SizeOfImage SizeOfHeaders CheckSum
            Subsystem DllCharacteristics
            SizeOfStackReserve SizeOfStackCommit SizeOfHeapReserve SizeOfHeapCommit
            LoaderFlags NumberOfRvaAndSizes
          ]
          @optional_header = keys.zip(optional_header_raw).to_h

          @optional_header[:DataDirectories] = parse_data_directories(raw, optional_header_offset + 112, @optional_header[:NumberOfRvaAndSizes])

          section_headers_offset = optional_header_offset + 112 + @optional_header[:NumberOfRvaAndSizes] * 8
          @optional_header[:SectionHeaders] = []
          @sections = []

          @file_header[:NumberOfSections].times do |i|
            section_header_raw = raw.byteslice(section_headers_offset + i * 40, 40).unpack('a8 L< L< L< L< L< L< S< S< L<')
            keys = %i[
              Name VirtualSize VirtualAddress SizeOfRawData PointerToRawData
              PointerToRelocations PointerToLinenumbers NumberOfRelocations
              NumberOfLinenumbers Characteristics
            ]
            @optional_header[:SectionHeaders] << keys.zip(section_header_raw).to_h
            
            section_name = @optional_header[:SectionHeaders].last[:Name].strip
            section_size = @optional_header[:SectionHeaders].last[:SizeOfRawData]
            section_offset = @optional_header[:SectionHeaders].last[:PointerToRawData]
            
            @sections << { :name => @optional_header[:SectionHeaders].last[:Name].strip, :data => raw.byteslice(section_offset, section_size) }

          end
        end
        

        def patch_dos_header
          @dos_header[:e_res2] = "\x00"*20
          @dos_header[:e_res] = "\x00"*8
          @dos_header[:e_oemid] = 0
          @dos_header[:e_oeminfo] = 0
        end

        def rebuild_pe
          oh = @optional_header

          # Compute new SizeOfHeaders: all header bytes up through the last section header,
          # rounded up to FileAlignment. This is the only correct way — just adding the raw
          # e_lfanew delta doesn't guarantee the result stays FileAlignment-aligned.
          nt_headers_end = @e_lfanew + 4 + 20 + @file_header[:SizeOfOptionalHeader] + @file_header[:NumberOfSections] * 40
          new_headers_size = align_up(nt_headers_end, FILE_ALIGN)

          # File-offset delta: how much all PointerToRawData values must shift.
          # Both new_headers_size and orig_headers_size are FileAlignment multiples,
          # so file_offset_delta is always FileAlignment-aligned — section pointers stay valid.
          orig_headers_size = oh[:SectionHeaders].first&.dig(:PointerToRawData) || oh[:SizeOfHeaders]
          file_offset_delta = new_headers_size - orig_headers_size

          # DOS header (64 bytes) — e_lfanew updated to the new offset
        #  out = [
        #    @dos_header[:e_magic],
        #    @dos_header[:e_cblp], @dos_header[:e_cp], @dos_header[:e_crlc],
        #    @dos_header[:e_cparhdr], @dos_header[:e_minalloc], @dos_header[:e_maxalloc],
        #    @dos_header[:e_ss], @dos_header[:e_sp], @dos_header[:e_csum],
        #    @dos_header[:e_ip], @dos_header[:e_cs], @dos_header[:e_lfarlc],
        #    @dos_header[:e_ovno], @dos_header[:e_res],
        #    @dos_header[:e_oemid], @dos_header[:e_oeminfo],
        #    @dos_header[:e_res2], @e_lfanew
        #  ].pack('a2 S< S< S< S< S< S< S< S< S< S< S< S< S< a8 S< S< a20 l<')
          

          out = [
            @dos_header[:e_magic],
            @dos_header[:e_cblp], @dos_header[:e_cp], @dos_header[:e_crlc],
            @dos_header[:e_cparhdr], @dos_header[:e_minalloc], @dos_header[:e_maxalloc],
            @dos_header[:e_ss], @dos_header[:e_sp], @dos_header[:e_csum],
            @dos_header[:e_ip], @dos_header[:e_cs], @dos_header[:e_lfarlc],
            @dos_header[:e_ovno], @dos_header[:e_res],
            @dos_header[:e_oemid], @dos_header[:e_oeminfo],
            @dos_header[:e_res2], @e_lfanew
          ].pack('a2 S< S< S< S< S< S< S< S< S< S< S< S< S< a8 S< S< a20 l<')

          # DOS stub region (bytes 64..@e_lfanew-1) — DOS_STUB_CODE, zero-padded to fit
          stub_area = @e_lfanew - 64
          out << DOS_STUB_CODE.b.ljust(stub_area, "\x00".b).byteslice(0, stub_area)

          # PE signature
          out << @nt_header_signature

          # COFF file header (20 bytes)
          out << [
            @file_header[:Machine],
            @file_header[:NumberOfSections],
            @file_header[:TimeDateStamp],
            @file_header[:PointerToSymbolTable],
            @file_header[:NumberOfSymbols],
            @file_header[:SizeOfOptionalHeader],
            @file_header[:Characteristics]
          ].pack('S< S< L< L< L< S< S<')

          # Optional header — AddressOfEntryPoint is an RVA (virtual address space),
          # not a file offset, so it must NOT be adjusted by file_offset_delta.
          # SizeOfHeaders is replaced with the freshly computed new_headers_size.
          out << [
            oh[:Magic], oh[:MajorLinkerVersion], oh[:MinorLinkerVersion],
            oh[:SizeOfCode], oh[:SizeOfInitializedData], oh[:SizeOfUninitializedData],
            oh[:AddressOfEntryPoint], oh[:BaseOfCode],
            oh[:ImageBase], oh[:SectionAlignment], oh[:FileAlignment],
            oh[:MajorOperatingSystemVersion], oh[:MinorOperatingSystemVersion],
            oh[:MajorImageVersion], oh[:MinorImageVersion],
            oh[:MajorSubsystemVersion], oh[:MinorSubsystemVersion],
            oh[:Win32VersionValue], oh[:SizeOfImage], new_headers_size,
            oh[:CheckSum], oh[:Subsystem], oh[:DllCharacteristics],
            oh[:SizeOfStackReserve], oh[:SizeOfStackCommit],
            oh[:SizeOfHeapReserve], oh[:SizeOfHeapCommit],
            oh[:LoaderFlags], oh[:NumberOfRvaAndSizes]
          ].pack('S< C C L< L< L< L< L< Q< L< L< S< S< S< S< S< S< L< L< L< L< S< S< Q< Q< Q< Q< L< L<')

          # Data directories (8 bytes each)
          oh[:DataDirectories].each do |dir|
            out << [dir[:rva], dir[:size]].pack('L< L<')
          end

          # Section headers (40 bytes each) — PointerToRawData shifted by file_offset_delta
          oh[:SectionHeaders].each do |sh|
            out << [
              sh[:Name], sh[:VirtualSize], sh[:VirtualAddress],
              sh[:SizeOfRawData], sh[:PointerToRawData] + file_offset_delta,
              sh[:PointerToRelocations], sh[:PointerToLinenumbers],
              sh[:NumberOfRelocations], sh[:NumberOfLinenumbers],
              sh[:Characteristics]
            ].pack('a8 L< L< L< L< L< L< S< S< L<')
          end

          # Pad headers to new_headers_size so section data starts at the correct file offset
          out = out.b.ljust(new_headers_size, "\x00".b)

          # Append raw section data
          oh[:SectionHeaders].each_with_index do |sh, i|
            section_data = (@sections[i] && @sections[i][:data]) || ''.b
            out << section_data.b.ljust(sh[:SizeOfRawData], "\x00".b)
          end
          
          patch_checksum(out)
        end

        
        def add_import_section

        end

        def build_from_c(c_source)
          # cpu     = Metasm::X86_64.new
          # headers = Compiler::Headers::Windows.new
          # source  = Compiler::Utils.normalize_code(c_source, headers)
          # pe      = Metasm::PE.compile_c(cpu, source)
          # raw     = pe.encode

          raw = Metasploit::Framework::Compiler::Windows.compile_c(c_source, :exe, Metasm::X86_64.new)
          load_pe(raw)
          
          # Do the magic
          #----------------
          patch_dos_header
          add_import_section

          #----------------
          new_raw = rebuild_pe
          return new_raw
        end

        def patch_checksum(pe_bytes)
          pe_bytes = pe_bytes.b

          lfanew = pe_bytes[0x3C, 4].unpack1('V')
          chksum_off = lfanew + 4 + 20 + 64

          pe_bytes[chksum_off, 4] = "\x00\x00\x00\x00".b

          # Pad to even length for WORD-wise iteration
          data = pe_bytes.bytesize.odd? ? pe_bytes + "\x00".b : pe_bytes

          sum = 0
          data.unpack('v*').each do |word|
            sum += word
            sum = (sum & 0xFFFF) + (sum >> 16) if sum > 0xFFFF
          end
          sum += pe_bytes.bytesize

          pe_bytes[chksum_off, 4] = [sum & 0xFFFFFFFF].pack('V')
          pe_bytes
        end

        private

        def align_up(value, boundary)
          ((value + boundary - 1) / boundary) * boundary
        end

      end
    end
  end
end
