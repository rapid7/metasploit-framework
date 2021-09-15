# -*- coding: binary -*-
#
# A mixin used for providing Modules with post-exploitation options and helper methods
#
module Msf::PostMixin

  include Msf::Auxiliary::Report

  include Msf::Module::HasActions
  include Msf::Post::Common

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_config_sysinfo
            ]
          }
        }
      )
    )

    register_options( [
      Msf::OptInt.new('SESSION', [ true, "The session to run this module on." ])
    ] , Msf::Post)

    # Default stance is active
    self.passive = info['Passive'] || false
    self.session_types = info['SessionTypes'] || []
  end

  #
  # Grabs a session object from the framework or raises {OptionValidateError}
  # if one doesn't exist.  Initializes user input and output on the session.
  #
  # @raise [OptionValidateError] if {#session} returns nil
  def setup
    alert_user

    unless session
      # Always fail if the session doesn't exist.
      raise Msf::OptionValidateError.new(['SESSION'])
    end

    # Check session readiness before compatibility so the session can be queried
    # for its platform, capabilities, etc.
    check_for_session_readiness if session.type == "meterpreter"

    incompatibility_reasons = session_incompatibility_reasons(session)
    if incompatibility_reasons.any?
      print_warning("SESSION may not be compatible with this module:")
      incompatibility_reasons.each do |reason|
        print_warning(" * #{reason}")
      end
    end

    # Msf::Exploit#setup for exploits, NoMethodError for post modules
    super rescue NoMethodError

    @session.init_ui(self.user_input, self.user_output)
    @sysinfo = nil
  end

  # Meterpreter sometimes needs a little bit of extra time to
  # actually be responsive for post modules. Default tries
  # and retries for 5 seconds.
  def check_for_session_readiness(tries=6)
    session_ready_count = 0
    session_ready = false
    until session.sys or session_ready_count > tries
      session_ready_count += 1
      back_off_period = (session_ready_count**2)/10.0
      select(nil,nil,nil,back_off_period)
    end
    session_ready = !!session.sys
    unless session_ready
      raise "The stdapi extension has not been loaded yet." unless session.tlv_enc_key.nil?
      raise "Could not get a hold of the session."
    end
    return session_ready
  end

  #
  # Default cleanup handler does nothing
  #
  def cleanup
  end

  #
  # Return the associated session or nil if there isn't one
  #
  # @return [Msf::Session]
  # @return [nil] if the id provided in the datastore does not
  #   correspond to a session
  def session
    # Try the cached one
    return @session if @session and not session_changed?

    if datastore["SESSION"]
      @session = framework.sessions.get(datastore["SESSION"].to_i)
    else
      @session = nil
    end

    @session
  end

  def session_display_info
    "Session: #{session.sid} (#{session.session_host})"
  end

  alias :client :session

  #
  # Cached sysinfo, returns nil for non-meterpreter sessions
  #
  # @return [Hash,nil]
  def sysinfo
    begin
      @sysinfo ||= session.sys.config.sysinfo
    rescue NoMethodError
      @sysinfo = nil
    end
    @sysinfo
  end

  #
  # Can be overridden by individual modules to add new commands
  #
  def post_commands
    {}
  end

  # Whether this module's {Msf::Exploit::Stance} is {Msf::Exploit::Stance::Passive passive}
  def passive?
    self.passive
  end

  #
  # Return a (possibly empty) list of all compatible sessions
  #
  # @return [Array]
  def compatible_sessions
    sessions = []
    framework.sessions.each do |sid, s|
      sessions << sid if session_compatible?(s)
    end
    sessions
  end

  #
  # Return false if the given session is not compatible with this module
  #
  # Checks the session's type against this module's
  # <tt>module_info["SessionTypes"]</tt> as well as examining platform
  # and arch compatibility.
  #
  # +sess_or_sid+ can be a Session object, Integer, or
  # String. In the latter cases it should be a key in
  # +framework.sessions+.
  #
  # @note Because it errs on the side of compatibility, a true return
  #   value from this method does not guarantee the module will work
  #   with the session. For example, ARCH_CMD modules can work on a
  #   variety of platforms and archs and thus return true in this check.
  #
  # @param sess_or_sid [Msf::Session,Integer,String]
  #   A session or session ID to compare against this module for
  #   compatibility.
  #
  def session_compatible?(sess_or_sid)
    session_incompatibility_reasons(sess_or_sid).empty?
  end

  #
  # Return the reasons why a session is incompatible.
  #
  # @return Array<String>
  def session_incompatibility_reasons(sess_or_sid)
    # Normalize the argument to an actual Session
    case sess_or_sid
    when ::Integer, ::String
      s = framework.sessions[sess_or_sid.to_i]
    when ::Msf::Session
      s = sess_or_sid
    end

    issues = []

    # Can't do anything without a session
    unless s
      issues << ['invalid session']
      return issues
    end

    # Can't be compatible if it's the wrong type
    if session_types
      issues << "incompatible session type: #{s.type}" unless session_types.include?(s.type)
    end

    # Check to make sure architectures match
    mod_arch = self.module_info['Arch']
    if mod_arch
      mod_arch = [mod_arch] unless mod_arch.kind_of?(Array)
      # Assume ARCH_CMD modules can work on supported SessionTypes since both shell and meterpreter types can execute commands
      issues << "incompatible session architecture: #{s.arch}" unless mod_arch.include?(s.arch) || mod_arch.include?(ARCH_CMD)
    end

    # Arch is okay, now check the platform.
    if self.platform && self.platform.kind_of?(Msf::Module::PlatformList)
      issues << "incompatible session platform: #{s.platform}" unless self.platform.supports?(Msf::Module::PlatformList.transform(s.platform))
    end

    if s.type == 'meterpreter'
      issues += meterpreter_session_incompatibility_reasons(s)
    end

    issues
  end

  #
  # True when this module is passive, false when active
  #
  # @return [Boolean]
  # @see passive?
  attr_reader :passive

  #
  # A list of compatible session types
  #
  # @return [Array]
  attr_reader :session_types

  protected

  attr_writer :passive
  attr_writer :session_types

  def session_changed?
    @ds_session ||= datastore["SESSION"]

    if (@ds_session != datastore["SESSION"])
      @ds_session = nil
      return true
    else
      return false
    end
  end

  #
  # Return the reasons why a meterpreter session is incompatible. Checks all specified meterpreter commands
  # are provided by the remote session
  #
  # @return Array<String>
  def meterpreter_session_incompatibility_reasons(session)
    cmd_name_wildcards = module_info.dig('Compat', 'Meterpreter', 'Commands') || []
    cmd_names = Rex::Post::Meterpreter::CommandMapper.get_command_names.select do |cmd_name|
      cmd_name_wildcards.any? { |cmd_name_wildcard| ::File.fnmatch(cmd_name_wildcard, cmd_name) }
    end

    unmatched_wildcards = cmd_name_wildcards.select { |cmd_name_wildcard| cmd_names.none? { |cmd_name| ::File.fnmatch(cmd_name_wildcard, cmd_name) } }
    unless unmatched_wildcards.empty?
      # This implies that there was a typo in one of the wildcards because it didn't match anything. This is a developer mistake.
      wlog("The #{fullname} module specified the following Meterpreter command wildcards that did not match anything: #{ unmatched_wildcards.join(', ') }")
    end

    cmd_ids = cmd_names.map { |name| Rex::Post::Meterpreter::CommandMapper.get_command_id(name) }

    # XXX: Remove this condition once the payloads gem has had another major version bump from 2.x to 3.x and
    # rapid7/metasploit-payloads#451 has been landed to correct the `enumextcmd` behavior on Windows. Until then, skip
    # proactive validation of Windows core commands. This is not the only instance of this workaround.
    if session.base_platform == 'windows'
      cmd_ids = cmd_ids.select do |cmd_id|
        !cmd_id.between?(
          Rex::Post::Meterpreter::ClientCore.extension_id,
          Rex::Post::Meterpreter::ClientCore.extension_id + Rex::Post::Meterpreter::COMMAND_ID_RANGE - 1
        )
      end
    end

    missing_cmd_ids = (cmd_ids - session.commands)
    unless missing_cmd_ids.empty?
      # If there are missing commands, try to load the necessary extension.

      # If core_loadlib isn't supported, then extensions can't be loaded
      return ['missing Meterpreter features: core can not be extended'] unless session.commands.include?(Rex::Post::Meterpreter::COMMAND_ID_CORE_LOADLIB)

      # Since core is already loaded, if the missing command is a core command then it's truly missing
      missing_core_cmd_ids = missing_cmd_ids.select do |cmd_id|
        cmd_id.between?(
          Rex::Post::Meterpreter::ClientCore.extension_id,
          Rex::Post::Meterpreter::ClientCore.extension_id + Rex::Post::Meterpreter::COMMAND_ID_RANGE - 1
        )
      end
      if missing_core_cmd_ids.any?
        return ["missing Meterpreter features: #{command_names_for(missing_core_cmd_ids)}"]
      end

      missing_extensions = missing_cmd_ids.map { |cmd_id| Rex::Post::Meterpreter::ExtensionMapper.get_extension_name(cmd_id) }.uniq
      missing_extensions.each do |ext_name|
        # If the extension is already loaded, the command is truly missing
        return ["missing Meterpreter features: #{command_names_for(missing_cmd_ids)}"] if session.ext.aliases.include?(ext_name)

        begin
          session.core.use(ext_name)
        rescue RuntimeError
          return ["unloadable Meterpreter extension: #{ext_name}"]
        end
      end
    end
    missing_cmd_ids -= session.commands
    return ["missing Meterpreter features: #{command_names_for(missing_cmd_ids)}"] unless missing_cmd_ids.empty?

    []
  end

  def command_names_for(command_ids)
    command_ids.map { |id| Rex::Post::Meterpreter::CommandMapper.get_command_name(id) }.join(', ')
  end
end
