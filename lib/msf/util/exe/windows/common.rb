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
  def self.to_exe_msi(framework, exe, opts = {})
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
  def self.replace_msi_buffer(pe, opts)
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
end