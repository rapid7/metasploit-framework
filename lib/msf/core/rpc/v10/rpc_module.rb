# -*- coding: binary -*-

require 'json'
require 'msf/util/document_generator'

module Msf
module RPC
class RPC_Module < RPC_Base

  # Returns a list of exploit names. The 'exploit/' prefix will not be included.
  #
  # @return [Hash] A list of exploit names. It contains the following key:
  #  * 'modules' [Array<string>] Exploit names, for example: ['windows/wins/ms04_045_wins']
  # @example Here's how you would use this from the client:
  #  rpc.call('module.exploits')
  def rpc_exploits
    { "modules" => self.framework.exploits.keys }
  end


  # Returns a list of evasion module names. The 'evasion/' prefix will not be included.
  #
  # @return [Hash] A list of evasion module names. It contains the following key:
  #  * 'modules' [Array<string>] Evasion names, for example: ['windows/windows_defender_exe']
  # @example Here's how you would use this from the client:
  #  rpc.call('module.evasion')
  def rpc_evasion
    { "modules" => self.framework.evasion.keys }
  end


  # Returns a list of auxiliary module names. The 'auxiliary/' prefix will not be included.
  #
  # @return [Hash] A list of auxiliary module names. It contains the following key:
  #  * 'modules' [Array<string>] Auxiliary module names, for example: ['vsploit/pii/web_pii']
  # @example Here's how you would use this from the client:
  #  rpc.call('module.auxiliary')
  def rpc_auxiliary
    { "modules" => self.framework.auxiliary.keys }
  end


  # Returns a list of payload module names or a hash with payload module names as keys to hashes
  # that contain the module information fields requested. The 'payload/' prefix will not be included.
  #
  # @param module_info [String] Comma-separated list of module information field names.
  # If this is nil, then only module names are returned. Default: nil
  # @param arch [String] Comma-separated list of one or more architectures that
  # the module must support. The module need only support one of the architectures
  # to be included, not all architectures. Default: nil
  #
  # @return [Hash] If module_info is nil, a list of payload module names. It contains the following key:
  #  * 'modules' [Array<String>] Payload module names, for example: ['windows/x64/shell_reverse_tcp']
  # If module_info is not nil, payload module names as keys to hashes that contain the requested module
  # information fields. It contains the following key:
  #  * 'modules' [Hash] for example:
  #    {"windows/x64/shell_reverse_tcp"=>{"name"=>"Windows x64 Command Shell, Reverse TCP Inline"}
  # @example Here's how you would use this from the client:
  #  rpc.call('module.payloads')
  def rpc_payloads(module_info = nil, arch = nil)
    module_info_contains_size = false

    unless module_info.nil?
      module_info = module_info.strip.split(',').map(&:strip)
      module_info.map!(&:to_sym)
      module_info_contains_size = module_info.include?(:size)
    end

    unless arch.nil?
      arch = arch.strip.split(',').map(&:strip)
    end

    data = module_info.nil? ? [] : {}
    arch_filter = !arch.nil? && !arch.empty? ? arch : nil
    self.framework.payloads.each_module('Arch' => arch_filter) do |name, mod|
      if module_info.nil?
        data << name
      else
        module_instance = mod.new
        if !module_info_contains_size && mod.method_defined?(:generate)
          # Unless the size field is specified in module_info, modify the generate
          # method for the module instance in order to skip payload generation when
          # the size method is called by Msf::Serializer::Json.dump_module, thus
          # reducing the processing time.
          class << module_instance
            def generate
              ''
            end
          end
        end

        tmp_mod_info = ::JSON.parse(Msf::Serializer::Json.dump_module(module_instance), symbolize_names: true)
        data[name] = tmp_mod_info.select { |k,v| module_info.include?(k) }
      end
    end

    { "modules" => data }
  end

  # Returns a list of encoder module names or a hash with encoder module names as keys to hashes
  # that contain the module information fields requested. The 'encoder/' prefix will not be included.
  #
  # @param module_info [String] Comma-separated list of module information field names.
  # If this is nil, then only module names are returned. Default: nil
  # @param arch [String] Comma-separated list of one or more architectures that
  # the module must support. The module need only support one of the architectures
  # to be included, not all architectures. Default: nil
  #
  # @return [Hash] If module_info is nil, a list of encoder module names. It contains the following key:
  #  * 'modules' [Array<String>] Encoder module names, for example: ['x86/unicode_upper']
  # If module_info is not nil, encoder module names as keys to hashes that contain the requested module
  # information fields. It contains the following key:
  #  * 'modules' [Hash] for example:
  #    {"x86/unicode_upper"=>{"name"=>"Alpha2 Alphanumeric Unicode Uppercase Encoder", "rank"=>"Manual"}}
  # @example Here's how you would use this from the client:
  #  rpc.call('module.encoders')
  def rpc_encoders(module_info = nil, arch = nil)
    unless module_info.nil?
      module_info = module_info.strip.split(',').map(&:strip)
      module_info.map!(&:to_sym)
    end

    unless arch.nil?
      arch = arch.strip.split(',').map(&:strip)
    end

    data = module_info.nil? ? [] : {}
    arch_filter = !arch.nil? && !arch.empty? ? arch : nil
    self.framework.encoders.each_module('Arch' => arch_filter) do |name, mod|
      if module_info.nil?
        data << name
      else
        tmp_mod_info = ::JSON.parse(Msf::Serializer::Json.dump_module(mod.new), symbolize_names: true)
        data[name] = tmp_mod_info.select { |k,v| module_info.include?(k) }
      end
    end

    { "modules" => data }
  end

  # Returns a list of NOP module names or a hash with NOP module names as keys to hashes
  # that contain the module information fields requested. The 'nop/' prefix will not be included.
  #
  # @param module_info [String] Comma-separated list of module information field names.
  # If this is nil, then only module names are returned. Default: nil
  # @param arch [String] Comma-separated list of one or more architectures that
  # the module must support. The module need only support one of the architectures
  # to be included, not all architectures. Default: nil
  #
  # @return [Hash] If module_info is nil, a list of NOP module names. It contains the following key:
  #  * 'modules' [Array<String>] NOP module names, for example: ['x86/single_byte']
  # If module_info is not nil, NOP module names as keys to hashes that contain the requested module
  # information fields. It contains the following key:
  #  * 'modules' [Hash] for example:
  #    {"x86/single_byte"=>{"name"=>"Single Byte", "rank"=>"Normal"}}
  # @example Here's how you would use this from the client:
  #  rpc.call('module.nops')
  def rpc_nops(module_info = nil, arch = nil)
    unless module_info.nil?
      module_info = module_info.strip.split(',').map(&:strip)
      module_info.map!(&:to_sym)
    end

    unless arch.nil?
      arch = arch.strip.split(',').map(&:strip)
    end

    data = module_info.nil? ? [] : {}
    arch_filter = !arch.nil? && !arch.empty? ? arch : nil
    self.framework.nops.each_module('Arch' => arch_filter) do |name, mod|
      if module_info.nil?
        data << name
      else
        tmp_mod_info = ::JSON.parse(Msf::Serializer::Json.dump_module(mod.new), symbolize_names: true)
        data[name] = tmp_mod_info.select { |k,v| module_info.include?(k) }
      end
    end

    { "modules" => data }
  end

  # Returns a list of post module names. The 'post/' prefix will not be included.
  #
  # @return [Hash] A list of post module names. It contains the following key:
  #  * 'modules' [Array<string>] Post module names, for example: ['windows/wlan/wlan_profile']
  # @example Here's how you would use this from the client:
  #  rpc.call('module.post')
  def rpc_post
    { "modules" => self.framework.post.keys }
  end


  # Returns detailed information about a module in HTML.
  #
  # @return [String] HTML file.
  # @example Here's how you would use this from the client:
  #  rpc.call('module.info_html', 'exploit', 'windows/smb/ms08_067_netapi')
  def rpc_info_html(mtype, mname)
    m = _find_module(mtype, mname)
    Msf::Util::DocumentGenerator.get_module_document(m)
  end


  # Returns the metadata for a module.
  #
  # @param [String] mtype Module type. Supported types include (case-sensitive):
  #                       * exploit
  #                       * auxiliary
  #                       * post
  #                       * nop
  #                       * payload
  # @param [String] mname Module name. For example: 'windows/wlan/wlan_profile'.
  # @raise [Msf::RPC::Exception] Module not found (either the wrong type or name).
  # @return [Hash] The module's metadata. The exact keys you will get depends on the module.
  # @example Here's how you would use this from the client:
  #  # This gives us the metadata of ms08_067_netapi
  #  rpc.call('module.info', 'exploit', 'windows/smb/ms08_067_netapi')
  def rpc_info(mtype, mname)
    m = _find_module(mtype,mname)
    res = module_short_info(m)
    res['description'] = Rex::Text.compress(m.description)
    res['license'] = m.license
    res['filepath'] = m.file_path
    res['arch'] = m.arch.map { |x| x.to_s }
    res['platform'] = m.platform.platforms.map { |x| x.to_s }
    res['authors'] = m.author.map { |a| a.to_s }
    res['privileged'] = m.privileged?

    res['references'] = []
    m.references.each do |r|
      res['references'] << [r.ctx_id, r.ctx_val]
    end

    if m.type == 'exploit' || m.type == 'evasion'
      res['targets'] = {}
      m.targets.each_index do |i|
        res['targets'][i] = m.targets[i].name
      end

      if (m.default_target)
        res['default_target'] = m.default_target
      end

      # Some modules are a combination, which means they are actually aggressive
      res['stance'] = m.stance.to_s.index('aggressive') ? 'aggressive' : 'passive'
    end

    if m.type == 'auxiliary' || m.type == 'post'
      res['actions'] = {}
      m.actions.each_index do |i|
        res['actions'][i] = m.actions[i].name
      end

      if m.default_action
        res['default_action'] = m.default_action
      end

      if m.type == 'auxiliary'
        res['stance'] = m.passive? ? 'passive' : 'aggressive'
      end
    end

    opts = {}
    m.options.each_key do |k|
      o = m.options[k]
      opts[k] = {
        'type'     => o.type,
        'required' => o.required,
        'advanced' => o.advanced,
        'desc'     => o.desc
      }

      opts[k]['default'] = o.default unless o.default.nil?
      opts[k]['enums'] = o.enums if o.enums.length > 1
    end
    res['options'] = opts

    res
  end

  def module_short_info(m)
    res = {}
    res['type'] = m.type
    res['name'] = m.name
    res['fullname'] = m.fullname
    res['rank'] = RankingName[m.rank].to_s
    res['disclosuredate'] = m.disclosure_date.nil? ? "" : m.disclosure_date.strftime("%Y-%m-%d")
    res
  end

  def rpc_search(match)
    matches = []
    self.framework.search(match).each do |m|
      matches << module_short_info(m)
    end
    matches
  end

  # Returns the compatible payloads for a specific exploit.
  #
  # @param [String] mname Exploit module name. For example: 'windows/smb/ms08_067_netapi'.
  # @raise [Msf::RPC::Exception] Module not found (wrong name).
  # @return [Hash] The exploit's compatible payloads. It contains the following key:
  #  * 'payloads' [Array<string>] A list of payloads. For example: ['generic/custom']
  # @example Here's how you would use this from the client:
  #  rpc.call('module.compatible_payloads', 'windows/smb/ms08_067_netapi')
  def rpc_compatible_payloads(mname)
    m   = _find_module('exploit',mname)
    res = {}
    res['payloads'] = []
    m.compatible_payloads.each do |k|
      res['payloads'] << k[0]
    end

    res
  end

  alias :rpc_compatible_exploit_payloads :rpc_compatible_payloads


  # Returns the compatible payloads for a specific evasion module.
  #
  # @param [String] mname Evasion module name. For example: 'windows/windows_defender_exe'
  # @raise [Msf::RPC::Exception] Module not found (wrong name).
  # @return [Hash] The evasion module's compatible payloads. It contains the following key:
  #  * 'payloads' [Array<String>] A list of payloads.
  # @example Here's how you would use this from the client:
  #  rpc.call('module.compatible_evasion_payloads', 'windows/windows_defender_exe')
  def rpc_compatible_evasion_payloads(mname)
    m = _find_module('evasion', mname)
    res = {}
    res['payloads'] = []

    m.compatible_payloads.each do |k|
      res['payloads'] << k[0]
    end

    res
  end


  # Returns the compatible sessions for a specific post module.
  #
  # @param [String] mname Post module name. For example: 'windows/wlan/wlan_profile'.
  # @raise [Msf::RPC::Exception] Module not found (wrong name).
  # @return [Hash] The post module's compatible sessions. It contains the following key:
  #  * 'sessions' [Array<Integer>] A list of session IDs.
  # @example Here's how you would use this from the client:
  #  rpc.call('module.compatible_sessions', 'windows/wlan/wlan_profile')
  def rpc_compatible_sessions(mname)
    m   = _find_module('post',mname)
    res = {}
    res['sessions'] = m.compatible_sessions

    res
  end


  # Returns the compatible target-specific payloads for an exploit.
  #
  # @param [String] mname Exploit module name. For example: 'windows/smb/ms08_067_netapi'
  # @param [Integer] target A specific target the exploit module provides.
  # @raise [Msf::RPC::Exception] Module not found (wrong name).
  # @return [Hash] The exploit's target-specific payloads. It contains the following key:
  #  * 'payloads' [Array<string>] A list of payloads.
  # @example Here's how you would use this from the client:
  #  # Find all the compatible payloads for target 1 (Windows 2000 Universal)
  #  rpc.call('module.target_compatible_payloads', 'windows/smb/ms08_067_netapi', 1)
  def rpc_target_compatible_payloads(mname, target)
    m   = _find_module('exploit',mname)
    res = {}
    res['payloads'] = []
    m.datastore['TARGET'] = target.to_i
    m.compatible_payloads.each do |k|
      res['payloads'] << k[0]
    end

    res
  end

  alias :rpc_target_compatible_exploit_payloads :rpc_target_compatible_payloads


  # Returns the compatible target-specific payloads for an evasion module.
  #
  # @param [String] mname Evasion module name. For example: windows/windows_defender_exe
  # @param [Integer] target A specific target the evasion module provides.
  # @raise [Msf::RPC::Exception] Module not found (wrong name)
  # @return [Hash] The evasion module's target-specific payloads. It contains the following key:
  #  * 'payloads' [Array<String>] A list of payloads.
  # @example Here's how you would use this from the client:
  #  rpc.call('module.target_compatible_evasion_payloads', 'windows/windows_defender_exe')
  def rpc_target_compatible_evasion_payloads(mname, target)
    m   = _find_module('evasion',mname)
    res = {}
    res['payloads'] = []
    m.datastore['TARGET'] = target.to_i
    m.compatible_payloads.each do |k|
      res['payloads'] << k[0]
    end

    res
  end


  # Returns the module's datastore options.
  #
  # @param [String] mtype Module type. Supported types include (case-sensitive):
  #                       * exploit
  #                       * auxiliary
  #                       * post
  #                       * nop
  #                       * payload
  # @param [String] mname Module name. For example: 'windows/wlan/wlan_profile'.
  # @raise [Msf::RPC::Exception] Module not found (either wrong type or name).
  # @return [Hash] The module's datastore options. This will actually give you each option's
  #                data type, requirement state, basic/advanced type, description, default value, etc.
  # @example Here's how you would use this from the client:
  #  rpc.call('module.options', 'exploit', 'windows/smb/ms08_067_netapi')
  def rpc_options(mtype, mname)
    m = _find_module(mtype,mname)
    res = {}

    m.options.each_key do |k|
      o = m.options[k]
      res[k] = {
        'type'     => o.type,
        'required' => o.required,
        'advanced' => o.advanced,
        'evasion'  => o.evasion,
        'desc'     => o.desc
      }

      if(not o.default.nil?)
        res[k]['default'] = o.default
      end

      if(o.enums.length > 1)
        res[k]['enums'] = o.enums
      end
    end

    res
  end


  # Executes a module.
  #
  # @param [String] mtype Module type. Supported types include (case-sensitive):
  #                       * exploit
  #                       * auxiliary
  #                       * post
  #                       * payload
  #                       * evasion
  # @param [String] mname Module name. For example: 'windows/smb/ms08_067_netapi'.
  # @param [Hash] opts Options for the module (such as datastore options).
  # @raise [Msf::RPC::Exception] Module not found (either wrong type or name).
  # @note If you get exploit sessions via the RPC service, know that only the RPC clients
  #       have access to those sessions. Framework msfconsole will not be able to use or
  #       even see these sessions, because it belongs to a different framework instance.
  #       However, this restriction does not apply to the database.
  # @return [Hash] It contains the following keys:
  #  * 'job_id' [Integer] Job ID.
  #  * 'uuid' [String] UUID.
  # @example Here's how you would use this from the client:
  #  # Starts a windows/meterpreter/reverse_tcp on port 6669
  #  opts = {'LHOST' => '0.0.0.0', 'LPORT'=>6669, 'PAYLOAD'=>'windows/meterpreter/reverse_tcp'}
  #  rpc.call('module.execute', 'exploit', 'multi/handler', opts)
  def rpc_execute(mtype, mname, opts)
    mod = _find_module(mtype,mname)
    case mtype
      when 'exploit'
        _run_exploit(mod, opts)
      when 'auxiliary'
        _run_auxiliary(mod, opts)
      when 'payload'
        _run_payload(mod, opts)
      when 'post'
        _run_post(mod, opts)
      when 'evasion'
        _run_evasion(mod, opts)
    end

  end

  # Runs the check method of a module.
  #
  # @param [String] mtype Module type. Supported types include (case-sensitive):
  #                       * exploit
  #                       * auxiliary
  # @param [String] mname Module name. For example: 'windows/smb/ms08_067_netapi'.
  # @param [Hash] opts Options for the module (such as datastore options).
  # @raise [Msf::RPC::Exception] Module not found (either wrong type or name).
  # @return
  def rpc_check(mtype, mname, opts)
    mod = _find_module(mtype,mname)
    case mtype
    when 'exploit'
      _check_exploit(mod, opts)
    when 'auxiliary'
      _run_auxiliary(mod, opts)
    else
      error(500, "Invalid Module Type: #{mtype}")
    end
  end

  # TODO: expand these to take a list of UUIDs or stream with event data if
  # required for performance
  def rpc_results(uuid)
    if r = self.framework.results[uuid]
      if r[:error]
        {"status" => "errored", "error" => r[:error]}
      else
        {"status" => "completed", "result" => r[:result]}
      end
    elsif self.framework.running.include? uuid
      {"status" => "running"}
    elsif self.framework.ready.include? uuid
      {"status" => "ready"}
    else
      error(404, "Results not found for module instance #{uuid}")
    end
  end

  def rpc_ack(uuid)
    {"success" => !!self.framework.results.delete(uuid)}
  end

  # Returns a list of executable format names.
  #
  # @return [Array<String>] A list of executable format names, for example: ["exe"]
  # @example Here's how you would use this from the client:
  #  rpc.call('module.executable_formats')
  def rpc_executable_formats
    ::Msf::Util::EXE.to_executable_fmt_formats
  end

  # Returns a list of transform format names.
  #
  # @return [Array<String>] A list of transform format names, for example: ["powershell"]
  # @example Here's how you would use this from the client:
  #  rpc.call('module.transform_formats')
  def rpc_transform_formats
    ::Msf::Simple::Buffer.transform_formats
  end

  # Returns a list of encryption format names.
  #
  # @return [Array<String>] A list of encryption format names, for example: ["aes256"]
  # @example Here's how you would use this from the client:
  #  rpc.call('module.encryption_formats')
  def rpc_encryption_formats
    ::Msf::Simple::Buffer.encryption_formats
  end

  # Returns a list of platform names.
  #
  # @return [Array<String>] A list of platform names, for example: ["linux"]
  # @example Here's how you would use this from the client:
  #  rpc.call('module.platforms')
  def rpc_platforms
    supported_platforms = []
    Msf::Module::Platform.subclasses.each { |c| supported_platforms << c.realname.downcase }
    supported_platforms.sort
  end

  # Returns a list of architecture names.
  #
  # @return [Array<String>] A list of architecture names, for example: ["x64"]
  # @example Here's how you would use this from the client:
  #  rpc.call('module.architectures')
  def rpc_architectures
    supported_archs = ARCH_ALL.dup
    supported_archs.sort
  end

  # Returns a list of encoding formats.
  #
  # @return [Array<String>] Encoding formats.
  # @example Here's how you would use this from the client:
  #  rpc.call('module.encode_formats')
  def rpc_encode_formats
    # Supported formats
    Msf::Simple::Buffer.transform_formats + Msf::Util::EXE.to_executable_fmt_formats
  end


  # Encodes data with an encoder.
  #
  # @param [String] data Data to encode.
  # @param [encoder] encoder Encoder module name. For example: 'x86/single_byte'.
  # @param [Hash] options Encoding options, such as:
  # @option options [String] 'format' Encoding format.
  # @option options [String] 'badchars' Bad characters.
  # @option options [String] 'platform' Platform.
  # @option options [String] 'arch' Architecture.
  # @option options [Integer] 'ecount' Number of times to encode.
  # @option options [TrueClass] 'inject' To enable injection.
  # @option options [String] 'template' The template file (an executable).
  # @option options [String] 'template_path' Template path.
  # @option options [String] 'addshellcode' Custom shellcode.
  # @raise [Msf::RPC::Exception] Error could be one of these:
  #                              * 500 Invalid format
  #                              * 500 Failure to encode
  # @return The encoded data. It contains the following key:
  #  * 'encoded' [String] The encoded data in the format you specify.
  # @example Here's how you would use this from the client:
  #  # This will encode 'AAAA' with shikata_ga_nai, and prints the following:
  #  # unsigned char buf[] =
  #  # "\xba\x9e\xb5\x91\x66\xdb\xd2\xd9\x74\x24\xf4\x5f\x29\xc9\xb1"
  #  # "\x01\x31\x57\x15\x03\x57\x15\x83\xc7\x04\xe2\x6b\xf4\xd0\x27";
  #  result = rpc.call('module.encode', 'AAAA', 'x86/shikata_ga_nai', {'format'=>'c'})
  #  puts result['encoded']
  def rpc_encode(data, encoder, options)
    # Load supported formats
    supported_formats = Msf::Simple::Buffer.transform_formats + Msf::Util::EXE.to_executable_fmt_formats

    if (fmt = options['format'])
      if not supported_formats.include?(fmt)
        error(500, "Invalid Format: #{fmt}")
      end
    end

    badchars = ''
    if options['badchars']
      badchars = options['badchars']
    end

    platform = nil
    if options['platform']
      platform = Msf::Module::PlatformList.transform(options['platform'])
    end

    arch = nil
    if options['arch']
      arch = options['arch']
    end

    ecount = 1
    if options['ecount']
      ecount = options['ecount'].to_i
    end

    exeopts = {
      :inject => options['inject'],
      :template => options['altexe'],
      :template_path => options['exedir']
    }

    # If we were given addshellcode for a win32 payload,
    # create a double-payload; one running in one thread, one running in the other
    if options['addshellcode']
      buf = Msf::Util::EXE.win32_rwx_exec_thread(buf,0,'end')
      file = ::File.new(options['addshellcode'])
      file.binmode
      buf << file.read
      file.close
    end

    enc = self.framework.encoders.create(encoder)

    begin
      # Imports options
      enc.datastore.update(options)

      raw  = data.unpack("C*").pack("C*")

      1.upto(ecount) do |iteration|
        # Encode it up
        raw = enc.encode(raw, badchars, nil, platform)
      end

      output = Msf::Util::EXE.to_executable_fmt(self.framework, arch, platform, raw, fmt, exeopts)

      if not output
        fmt ||= "ruby"
        output = Msf::Simple::Buffer.transform(raw, fmt)
      end

      # How to warn?
      #if exeopts[:fellback]
      #  $stderr.puts(OutError + "Warning: Falling back to default template: #{exeopts[:fellback]}")
      #end

      { "encoded" => output.to_s }
    rescue => e
      error(500, "#{enc.refname} failed: #{e} #{e.backtrace}")
    end
  end

private

  def _find_module(mtype,mname)

    if mname !~ /^(exploit|payload|nop|encoder|auxiliary|post|evasion)\//
      mname = mtype + "/" + mname
    end

    mod = self.framework.modules.create(mname)

    error(500, "Invalid Module") if not mod
    mod
  end

  def _run_exploit(mod, opts)
    s = Msf::Simple::Exploit.exploit_simple(mod, {
      'Payload'  => opts['PAYLOAD'],
      'Target'   => opts['TARGET'],
      'RunAsJob' => true,
      'Options'  => opts
    })
    {
      "job_id" => mod.job_id,
      "uuid" => mod.uuid
    }
  end

  def _run_auxiliary(mod, opts)
    uuid, job = Msf::Simple::Auxiliary.run_simple(mod, {
      'Action'   => opts['ACTION'],
      'RunAsJob' => true,
      'Options'  => opts
    })
    {
      "job_id" => job,
      "uuid" => uuid
    }
  end

  def _check_exploit(mod, opts)
    uuid, job = Msf::Simple::Exploit.check_simple(mod, {
        'RunAsJob' => true,
        'Options'  => opts
    })
    {
      "job_id" => job,
      "uuid" => uuid
    }
  end

  def _check_auxiliary(mod, opts)
    uuid, job = Msf::Simple::Auxiliary.check_simple(mod, {
        'Action'   => opts['ACTION'],
        'RunAsJob' => true,
        'Options'  => opts
    })
    {
      "job_id" => job,
      "uuid" => uuid
    }
  end

  def _run_post(mod, opts)
    Msf::Simple::Post.run_simple(mod, {
      'RunAsJob' => true,
      'Options'  => opts
    })
    {
      "job_id" => mod.job_id,
      "uuid" => mod.uuid
    }
  end

  def _run_evasion(mod, opts)
    Msf::Simple::Evasion.run_simple(mod, {
      'Payload'  => opts['PAYLOAD'],
      'Target'   => opts['TARGET'],
      'RunAsJob' => true,
      'Options'  => opts
    })

    {
      'job_id' => mod.job_id,
      'uuid'   => mod.uuid
    }
  end

  def _run_payload(mod, opts)
    badchars = opts['BadChars'] || ''
    fmt = opts['Format'] || 'raw'
    force = opts['ForceEncode'] || false
    template = opts['Template'] || nil
    plat = opts['Platform'] || nil
    keep = opts['KeepTemplateWorking'] || false
    force = opts['ForceEncode'] || false
    sled_size = opts['NopSledSize'].to_i || 0
    iter = opts['Iterations'].to_i || 0

    begin
      res = Msf::Simple::Payload.generate_simple(mod, {
        'BadChars'    => badchars,
        'Encoder'     => opts['Encoder'],
        'Format'      => fmt,
        'NoComment'   => true,
        'NopSledSize' => sled_size,
        'Options'     => opts,
        'ForceEncode' => force,
        'Template'    => template,
        'Platform'    => plat,
        'KeepTemplateWorking' => keep,
        'Iterations'  => iter
      })

      { "payload" => res }
    rescue ::Exception => e
      error(500, "failed to generate: #{e.message}")
    end
  end


end
end
end

