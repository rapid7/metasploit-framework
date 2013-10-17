# -*- coding: binary -*-
module Rex
module PeScan
module Analyze

  require "rex/ui/text/table"

  class Fingerprint
    attr_accessor :pe

    def initialize(pe)
      self.pe = pe
    end

    def config(param)
      @sigs = {}

      name = nil
      regx = ''
      epon = 0
      sidx = 0

      fd = File.open(param['database'], 'rb')
      fd.each_line do |line|
        case line
        when /^\s*#/
          next
        when /\[\s*(.*)\s*\]/
          if (name)
            @sigs[ name ] = [regx, epon]
          end
          name = $1 + " [#{ sidx+=1 }]"
          epon = 0
          next
        when /signature\s*=\s*(.*)/
          pat = $1.strip
          regx = ''
          pat.split(/\s+/).each do |c|
            next if c.length != 2
            regx << (c.index('?') ? '.' : "\\x#{c}")
          end
        when /ep_only\s*=\s*(.*)/
          epon = ($1 =~ /^T/i) ? 1 : 0
        end
      end

      if (name and ! @sigs[name])
        @sigs[ name ] = [regx, epon]
      end

      fd.close
    end

    def scan(param)
      config(param)

      epa = pe.hdr.opt.AddressOfEntryPoint
      buf = pe.read_rva(epa, 256) || ""

      @sigs.each_pair do |name, data|
        begin
        if (buf.match(Regexp.new('^' + data[0], nil, 'n')))
          $stdout.puts param['file'] + ": " + name
        end
        rescue RegexpError
          $stderr.puts "Invalid signature: #{name} #{data[0]}"
        end
      end
    end
  end

  class Information
    attr_accessor :pe

    def initialize(pe)
      self.pe = pe
    end

    def add_fields(tbl, obj, fields)
      fields.each do |name|
        begin
          tbl << [name, "0x%.8x" % obj.send(name)]
        rescue ::NoMethodError => e
          $stderr.puts "Invalid field #{name}"
        end
      end
    end

    def scan(param)

      $stdout.puts "\n\n"

      tbl = table("Image Headers", ['Name', 'Value'])
      add_fields(tbl, pe.hdr.file, %W{
        Characteristics
        SizeOfOptionalHeader
        PointerToSymbolTable
        TimeDateStamp
        NumberOfSections
        Machine
      })
      $stdout.puts tbl.to_s
      $stdout.puts "\n\n"

      tbl = table("Optional Image Headers", ['Name', 'Value'])
      add_fields(tbl, pe.hdr.opt, %W{
        ImageBase
        Magic
        MajorLinkerVersion
        MinorLinkerVersion
        SizeOfCode
        SizeOfInitializeData
        SizeOfUninitializeData
        AddressOfEntryPoint
        BaseOfCode
        BaseOfData
        SectionAlignment
        FileAlignment
        MajorOperatingSystemVersion
        MinorOperatingSystemVersion
        MajorImageVersion
        MinorImageVersion
        MajorSubsystemVersion
        MinorSubsystemVersion
        Win32VersionValue
        SizeOfImage
        SizeOfHeaders
        CheckSum
        Subsystem
        DllCharacteristics
        SizeOfStackReserve
        SizeOfStackCommit
        SizeOfHeapReserve
        SizeOfHeapCommit
        LoaderFlags
        NumberOfRvaAndSizes
      })

      $stdout.puts tbl.to_s
      $stdout.puts "\n\n"

      # Get DllCharacteristics (in Integer)
      dllcharacteristics = pe.hdr.opt.struct[23].value

      if (dllcharacteristics > 0)
        tbl = table("DllCharacteristics", ['Flag', 'Value'])

        # http://msdn.microsoft.com/en-us/library/ms680339(v=vs.85).aspx
        traits = {
          :ASLR      => 'False',  #IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
          :Integrity => 'False',  #IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
          :NX        => 'False',  #IMAGE_DLLCHARACTERISTICS_NX_COMPAT
          :Isolation => 'False',  #IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
          :SEH       => 'False',  #IMAGE_DLLCHARACTERISTICS_NO_SEH
          :Bind      => 'False',  #IMAGE_DLLCHARACTERISTICS_NO_BIND
          :WDM       => 'False',  #IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
          :Terminal  => 'False'   #IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
        }

        # Convert integer to an bit array
        c_bits = ("%32d" %dllcharacteristics.to_s(2)).split('').map { |e| e.to_i }.reverse

        # Check characteristics
        traits[:ASLR]      = 'True' if c_bits[6]  == 1  #0x0040
        traits[:Integrity] = 'True' if c_bits[7]  == 1  #0x0080
        traits[:NX]        = 'True' if c_bits[8]  == 1  #0x0100
        traits[:Isolation] = 'True' if c_bits[9]  == 1  #0x0200
        traits[:SEH]       = 'True' if c_bits[10] == 1  #0x0400
        traits[:Bind]      = 'True' if c_bits[11] == 1  #0x0800
        traits[:WDM]       = 'True' if c_bits[13] == 1  #2000
        traits[:Terminal]  = 'True' if c_bits[15] == 1  #0x8000

        # Putting results to table
        traits.each do |trait_name, trait_value|
          tbl << [trait_name, trait_value]
        end

        $stdout.puts tbl.to_s
        $stdout.puts "\n\n"
      end

      if (pe.exports)
        tbl = table("Exported Functions", ['Ordinal', 'Name', 'Address'])
        pe.exports.entries.each do |ent|
          tbl << [ent.ordinal, ent.name, "0x%.8x" % pe.rva_to_vma(ent.rva)]
        end
        $stdout.puts tbl.to_s
        $stdout.puts "\n\n"
      end

      # Rex::PeParsey::Pe doesn't seem to give us any offset information for each function,
      # which makes it difficult to calculate the actual addresses for them. So instead we
      # are using Metasm::COFF::ImportDirectory to do this task.  The ability to see
      # addresses is mainly for ROP.
      if (pe.imports)
        tbl = table("Imported Functions", ['Library', 'Address', 'Ordinal', 'Name'])
        exefmt = Metasm::AutoExe.orshellcode{ Metasm.const_get('x86_64').new }
        exe = exefmt.decode_file(pe._isource.file.path)
        ibase = pe.image_base
        exe_imports = exe.imports
        exe_imports.each do |lib|
          lib_name   = lib.libname
          ini_offset = lib.iat_p
          func_table = lib.imports
          offset     = 0
          func_table.each do |func|
            func_addr = "0x%08x" %(ibase + ini_offset + offset)
            tbl << [lib_name, func_addr, func.hint, func.name]
            offset += 4
          end
        end

        $stdout.puts tbl.to_s
        $stdout.puts "\n\n"
      end

      if(pe.config)
        tbl = table("Configuration Header", ['Name', 'Value'])
        add_fields(tbl, pe.config, %W{
          Size
          TimeDateStamp
          MajorVersion
          MinorVersion
          GlobalFlagsClear
          GlobalFlagsSet
          CriticalSectionDefaultTimeout
          DeCommitFreeBlockThreshold
          DeCommitTotalFreeThreshold
          LockPrefixTable
          MaximumAllocationSize
          VirtualMemoryThreshold
          ProcessAffinityMask
          ProcessHeapFlags
          CSDVersion
          Reserved1
          EditList
          SecurityCookie
          SEHandlerTable
          SEHandlerCount
        })
        $stdout.puts tbl.to_s
        $stdout.puts "\n\n"
      end


      if(pe.resources)
        tbl = table("Resources", ['ID', 'Language', 'Code Page', 'Size', 'Name'])
        pe.resources.keys.sort.each do |rkey|
          res = pe.resources[rkey]
          tbl << [rkey, res.lang, res.code, res.size, res.file]
        end
        $stdout.puts tbl.to_s
        $stdout.puts "\n\n"
      end

      tbl = table("Section Header", ["Name", "VirtualAddress", "SizeOfRawData", "Characteristics"])
      pe.sections.each do |sec|
        tbl << [ sec.name, *[sec.vma, sec.raw_size, sec.flags].map{|x| "0x%.8x" % x} ]
      end
      $stdout.puts tbl.to_s
      $stdout.puts "\n\n"

    end

    def table(name, cols)
      Rex::Ui::Text::Table.new(
        'Header'  => name,
        'Columns' => cols
      )
    end
  end


  class Ripper

    require "fileutils"

    attr_accessor :pe

    def initialize(pe)
      self.pe = pe
    end

    def scan(param)
      dest = param['dir']

      if (param['file'])
        dest = File.join(dest, File.basename(param['file']))
      end

      ::FileUtils.mkdir_p(dest)

      pe.resources.keys.sort.each do |rkey|
        res  = pe.resources[rkey]
        path = File.join(dest, rkey.split('/')[1] + '_' + res.file)

        fd = File.new(path, 'wb')
        fd.write(res.data)
        fd.close
      end
    end
  end

  class ContextMapDumper

    attr_accessor :pe

    def initialize(pe)
      self.pe = pe
    end

    def scan(param)
      dest = param['dir']
      path = ''

      ::FileUtils.mkdir_p(dest)

      if(not (param['dir'] and param['file']))
        $stderr.puts "No directory or file specified"
        return
      end

      if (param['file'])
        path = File.join(dest, File.basename(param['file']) + ".map")
      end

      fd = File.new(path, "wb")
      pe.all_sections.each do |section|

        # Skip over known bad sections
        next if section.name == ".data"
        next if section.name == ".reloc"

        offset = 0
        while offset < section.size
          byte = section.read(offset, 1)[0]
          if byte != 0
            chunkbase = pe.rva_to_vma(section.base_rva) + offset
            data = ''
            while byte != 0
              data << byte
              offset += 1
              byte = 0
              byte = section.read(offset, 1)[0] if offset < section.size
            end
            buff = nil
            buff = [ 0x01, chunkbase, data.length, data].pack("CNNA*") if data.length > 0

            fd.write(buff) if buff
          end
          offset += 1
        end

      end


      fd.close
    end
  end

# EOC

end
end
end

