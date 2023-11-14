# -*- coding: binary -*-
#
# frozen_string_literal: true

# A mixin used for providing Modules with post-exploitation options and helper methods
#
module Msf::OptionalSession
  include Msf::Auxiliary::Report

  include Msf::Module::HasActions
  include Msf::Post::Common

  def initialize(info = {})
    super

    if framework.features.enabled?(Msf::FeatureManager::SMB_SESSION_TYPE)
      register_options(
        [
          Msf::OptInt.new('SESSION', [ false, 'The session to run this module on' ]),
          Msf::Opt::RHOST(nil, false),
          Msf::Opt::RPORT(nil, false)
        ]
      )
    end


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

    unless session || !options['SESSION']&.required
      raise Msf::OptionValidateError, ['SESSION']
    end

    super

    @session.init_ui(user_input, user_output) if @session
    @sysinfo = nil
  end

  #
  # Default cleanup handler does nothing
  #
  def cleanup; end

  #
  # Return the associated session or nil if there isn't one
  #
  # @return [Msf::Session]
  # @return [nil] if the id provided in the datastore does not
  #   correspond to a session
  def session
    return nil unless framework.features.enabled?(Msf::FeatureManager::SMB_SESSION_TYPE)
    # Try the cached one
    return @session if @session && !session_changed?

    if datastore['SESSION']
      @session = framework.sessions.get(datastore['SESSION'].to_i)
    else
      @session = nil
    end

    @session
  end

  def session_display_info
    "Session: #{session.sid} (#{session.session_host})"
  end

  #
  # Can be overridden by individual modules to add new commands
  #
  def post_commands
    {}
  end

  # Whether this module's {Msf::Exploit::Stance} is {Msf::Exploit::Stance::Passive passive}
  def passive?
    passive
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
    if session_types && !session_types.include?(s.type)
      issues << "incompatible session type: #{s.type}"
    end

    # Check to make sure architectures match
    mod_arch = module_info['Arch']
    if mod_arch
      mod_arch = Array.wrap(mod_arch)
      # Assume ARCH_CMD modules can work on supported SessionTypes since both shell and meterpreter types can execute commands
      issues << "incompatible session architecture: #{s.arch}" unless mod_arch.include?(s.arch) || mod_arch.include?(ARCH_CMD)
    end

    # Arch is okay, now check the platform.
    if platform && platform.is_a?(Msf::Module::PlatformList) && !platform.supports?(Msf::Module::PlatformList.transform(s.platform))
      issues << "incompatible session platform: #{s.platform}"
    end

    # Check all specified meterpreter commands are provided by the remote session
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

  attr_writer :passive, :session_types

  def session_changed?
    @ds_session ||= datastore['SESSION']

    if (@ds_session != datastore['SESSION'])
      @ds_session = nil
      return true
    else
      return false
    end
  end
end
