require 'metasm'
require 'pry'
require 'pry-byebug'

module Metasploit
  module Framework
    module Compiler

      class Custom

        DOS_STUB = (
          "\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" \
          "This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00"
        ).b.freeze

        RICH_HEADER = ("\x7E\x13\x87\xAA\x3A\x72\xE9\xF9\x3A\x72\xE9\xF9\x3A\x72\xE9\xF9\x33\x0A\x7A\xF9\x30\x72\xE9\xF9\xF1\x1D\xE8\xF8\x38\x72\xE9\xF9\xF1\x1D\xEC\xF8\x2B\x72\xE9\xF9\xF1\x1D\xED\xF8\x30\x72\xE9\xF9\xF1\x1D\xEA\xF8\x39\x72\xE9\xF9\x61\x1A\xE8\xF8\x3F\x72\xE9\xF9\x3A\x72\xE8\xF9\x0A\x72\xE9\xF9\xBC\x02\xE0\xF8\x3B\x72\xE9\xF9\xBC\x02\x16\xF9\x3B\x72\xE9\xF9\xBC\x02\xEB\xF8\x3B\x72\xE9\xF9\x52\x69\x63\x68\x3A\x72\xE9\xF9\x00\x00\x00\x00\x00\x00\x00\x00").b.freeze
        
        COMMON_OFFSETS = [0x40, 0x80].freeze
        
        def DOSHeader(pe_entry=nil)
          e_lfanew = pe_entry || COMMON_OFFSETS.sample
          dos_header = [
            "MZ".b, # e_magic
            "\x00\x00".b, # e_cblp
            "\x00\x00".b, # e_cp
            "\x00\x00".b, # e_crlc
            "\x00\x00".b, # e_cparhdr
            "\x00\x00".b, # e_minalloc
            "\x00\x00".b, # e_maxalloc
            "\x00\x00".b, # e_ss
            "\x00\x00".b, # e_sp
            "\x00\x00".b, # e_csum
            "\x00\x00".b, # e_ip
            "\x00\x00".b, # e_cs
            "\x40\x00".b, # e_lfarlc (offset to the DOS stub)
            [e_lfanew].pack('V') # e_lfanew (offset to the PE header)
          ].join

          dos_header + DOS_STUB
        end
        
        def RichHeader
          RICH_HEADER
        end
        
        def OptionalHeader
        
        end

        def NTHeader(numberOfSections=1)
          optionalHeader = OptionalHeader()
          sizeOfOptionalHeader = optionalHeader.length
          [ 
            # DWORD Signature
            "PE\0\0".b, # Signature
            # IMAGE_FILE_HEADER FileHeader
            "\x64\x86".b, # Machine (0x14c for x86)
            [numberOfSections].pack('v'), # NumberOfSections
            "\x19\x5e\x42\x2a".b, # TimeDateStamp - TODO: randomize
            "\x00\x00\x00\x00".b, # PointerToSymbolTable
            "\x00\x00\x00\x00".b, # NumberOfSymbols
            [sizeOfOptionalHeader].pack('v'), # SizeOfOptionalHeader
            "\x02\x01".b # Characteristics (0x102 for executable) - TODO: randomize
            # IMAGE_OPTIONAL_HEADER OptionalHeader
            optionalHeader
          ].join
        end

        def self.compile_c(c_template, type=:exe, cpu=Metasm::Ia32.new)
          
          binding.pry

          raise NotImplementedError, "Other type than :exe is not supported." unless type == :exe
          
          
        end

      end
    end
  end
end
