class Msf::Analyze::Result

  attr_reader :datastore
  attr_reader :host
  attr_reader :invalid
  attr_reader :missing
  attr_reader :mod
  attr_reader :required

  def initialize(host:, mod:, framework:, available_creds: nil, payloads: nil, datastore: nil)
    @host = host
    @mod = mod
    @required = []
    @missing = []
    @invalid = []
    @datastore = datastore&.transform_keys(&:downcase) || Hash.new
    @available_creds = available_creds
    @wanted_payloads = payloads
    @framework = framework

    determine_likely_compatibility
  end

  def evaluate(with: @datastore, payloads: @wanted_payloads)
    @datastore = with
    @wanted_payloads = payloads

    determine_prerequisites
    self
  end

  # Returns state for module readiness.
  #
  # @return :sym the stateful result one of:
  #  * :READY_FOR_TEST, :REQUIRES_CRED, :REUSE_PREVIOUS_OPTIONS, :MISSING_REQUIRED_OPTION, :MISSING_PAYLOAD, :REQUIRES_SESSION, :NEEDS_TARGET_ACTION, :INVALID_OPTION, :NOT_APPLICABLE
  #
  # | State                   | Detailed Reason                                                                                                                                                                |
  # |-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
  # | READY_FOR_TEST          | Ready for Test - All required options have defaults                                                                                                                            |
  # | REQUIRES_CRED           | Requires DB Credentials - Required options have defaults except credential values - if db contains known credentials for required fields validation is possible                |
  # | REUSE_PREVIOUS_OPTIONS  | Reuse Previous Options-  Taken as an analysis option, process existing module runs to gather options set for same module on other hosts                                        |
  # | MISSING_REQUIRED_OPTION | Missing Required Options - Some options are not available requiring manual configuration                                                                                       |
  # | MISSING_PAYLOAD         | Missing Compatible Payload - Known host details and payload restrictions exclude all payloads                                                                                  |
  # | REQUIRES_SESSION        | Requires Session - Modules that require an existing session can cannot be executed as first entry point on targets                                                             |
  # | NEEDS_TARGET_ACTION     | Needs target action - Module that either start a service and need the target to respond in a way that may require user interaction. (Browser exploit, needs target reboot....) |
  # | INVALID_OPTION          | Options used in Result evaluation are invalid                                                                                                                                  |
  # | NOT_APPLICABLE          | Module is not applicable to the host                                                                                                                                           |
  def state
    if ready_for_test? || (@missing.empty? && @invalid.empty?)
      :READY_FOR_TEST
      # TODO: result eval can look for previous attempts to determine :REUSE_PREVIOUS_OPTIONS state
    else
      unless @missing.empty?
        if @missing.include?(:credential)
          :REQUIRES_CRED
        elsif @missing.include?(:payload_match)
          :MISSING_PAYLOAD
        elsif @missing.include?(:session)
          :REQUIRES_SESSION
        elsif @missing.include?(:os_match)
          :NOT_APPLICABLE
          # TODO: result eval check for module stance to determine :NEEDS_TARGET_ACTION state?
        else
          :MISSING_REQUIRED_OPTION
        end
      else
        :INVALID_OPTION
      end
    end
  end

  # Returns state for module readiness.
  # @return :String detailed sentence form description of result evaluation.
  def description
    if ready_for_test?
      "ready for testing"
    elsif @missing.empty? && @invalid.empty?
      # TODO? confirm vuln match in this class
      "has matching reference"
    else
      if missing_message.empty? || invalid_message.empty?
        missing_message + invalid_message
      else
        [missing_message, invalid_message].join(', ')
      end
    end
  end

  def match?
    !@missing.include? :os_match
  end

  def ready_for_test?
    @prerequisites_evaluated && @missing.empty? && @invalid.empty?
  end

  private

  def determine_likely_compatibility
    if matches_host_os?
      @datastore['rhost'] = @host.address
    else
      @missing << :os_match
    end

    if @mod.post_auth?
      unless @mod.default_cred? || has_service_cred? || has_datastore_cred?
        @missing << :credential
      end
    end
  end

  def determine_prerequisites
    mod_detail = @framework.modules.create(@mod.fullname)
    if mod_detail.nil?
      @required << :module_not_loadable
      return
    end
    @mod = mod_detail

    if @mod.respond_to?(:session_types) && @mod.session_types
      @required << :session

      if s = @host.sessions.alive.detect { |sess| matches_session?(sess) }
        @datastore['session'] = s.local_id.to_s
      else
        @missing << :session
      end
    end

    @mod.options.each_pair do |name, opt|
      @required << name if opt.required? && !opt.default.nil?
    end

    @datastore.each_pair do |k, v|
      @mod.datastore[k] = v
    end

    target_idx = @mod.respond_to?(:auto_targeted_index) ? @mod.auto_targeted_index(@host) : nil
    if target_idx
      @datastore['target'] = target_idx
      @mod.datastore['target'] = target_idx
    end

    # Must come after the target so we know we match the target we want.
    # TODO: feed available payloads into target selection
    if @wanted_payloads
      if p = @wanted_payloads.find { |p| @mod.is_payload_compatible?(p) }
        @datastore['payload'] = p
      else
        @missing << :payload_match
      end
    end

    @mod.validate
  rescue Msf::OptionValidateError => e
    unset_options = []
    bad_options = []

    e.options.each do |opt|
      if @mod.datastore[opt].nil?
        unset_options << opt
      else
        bad_options << opt
      end
    end

    @missing.concat unset_options
    @invalid.concat bad_options
  ensure
    @prerequisites_evaluated = true
  end

  def matches_session?(session)
    session.stype == 'meterpreter' || !!@mod.session_types&.include?(session.stype)
  end

  def required_sessions_list
    return "meterpreter" unless @mod.session_types&.any?

    @mod.session_types.join(' or ')
  end

  def has_service_cred?
    @available_creds&.any?
  end

  def has_datastore_cred?
    !!(@datastore['username'] && @datastore['password'])
  end

  # Determines if an exploit (mod, an instantiated module) is suitable for the host (host)
  # defined operating system. Returns true if the host.os isn't defined, if the module's target
  # OS isn't defined, if the module's OS is "unix" and the host's OS is not "windows," or if
  # the module's target is "php", "python", or "java." Or, of course, in the event the host.os
  # actually matches. This is a fail-open gate; if there's a doubt, assume the module will work
  # on this target.
  def matches_host_os?
    hos = @host.os_name&.downcase
    return true if hos.nil? || hos.empty?

    set = @mod.platform.split(',').map{ |x| x.downcase }
    return true if set.empty?

    # Special cases
    if set.include?('unix')
      # Skip archaic old HPUX bugs if we have a solid match against another OS
      return false if set.include?("hpux") && mod.refname.include?("hpux") && !hos.inlcude?("hpux")
      # Skip AIX bugs if we have a solid match against another OS
      return false if set.include?("aix") && mod.refname.include?("aix") && !hos.include?("aix")
      # Skip IRIX bugs if we have a solid match against another OS
      return false if set.include?("irix") && mod.refname.include?("irix") && !hos.include?("irix")

      return true if !hos.include?('windows')
    end

    return true if set.include?("php")
    return true if set.include?("python")
    return true if set.include?("java")

    set.each do |mos|
      return true if hos.include?(mos)
    end

    false
  end

  def missing_message
    @missing.map do |m|
      case m
      when :module_not_loadable
        "module not loadable"
      when :os_match
        "operating system does not match"
      when :session, "SESSION"
        "open #{required_sessions_list} session required"
      when :credential
        "credentials are required"
      when :payload_match
        "none of the requested payloads match"
      when String
        "option #{m.inspect} needs to be set"
      end
    end.uniq.join(', ')
  end

  def invalid_message
    @invalid.map do |o|
      case o
      when String
        "option #{o.inspect} is currently invalid"
      end
    end.join(', ')
  end

=begin
  # Tests for various service conditions by comparing the module's fullname (which
  # is basically a pathname) to the intended target service record. The service.info
  # column is tested against a regex in most/all cases and "false" is returned in the
  # event of a match between an incompatible module and service fingerprint.
  # TODO: fix and integrate
  def exploit_filter_by_service(mod, serv)

    # Filter out Unix vs Windows exploits for SMB services
    return true if (mod.fullname =~ /\/samba/ and serv.info.to_s =~ /windows/i)
    return true if (mod.fullname =~ /\/windows/ and serv.info.to_s =~ /samba|unix|vxworks|qnx|netware/i)
    return true if (mod.fullname =~ /\/netware/ and serv.info.to_s =~ /samba|unix|vxworks|qnx/i)

    # Filter out IIS exploits for non-Microsoft services
    return true if (mod.fullname =~ /\/iis\/|\/isapi\// and (serv.info.to_s !~ /microsoft|asp/i))

    # Filter out Apache exploits for non-Apache services
    return true if (mod.fullname =~ /\/apache/ and serv.info.to_s !~ /apache|ibm/i)

    false
  end
=end
end
