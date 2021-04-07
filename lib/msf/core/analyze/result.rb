class Msf::Analyze::Result

  attr_reader :datastore
  attr_reader :host
  attr_reader :missing
  attr_reader :mod
  attr_reader :required

  def initialize(host:, mod:, available_creds: nil, datastore: nil)
    @host = host
    @mod = mod
    @required = []
    @missing = []
    @datastore = datastore&.transform_keys(&:downcase) || Hash.new
    @available_creds = available_creds

    determine_likely_compatibility
  end

  def to_s
    if ready_for_test?
      "ready for testing"
    else
      missing.map do |m|
        case m
        when :os_match
          "operating system does not match"
        when :session
          "open #{required_sessions_list} session required"
        when :credential
          "credentials are required"
        end
      end.join(', ')
    end
  end

  def match?
    !missing.include? :os_match
  end

  def ready_for_test?
    missing.empty?
  end

  private

  def determine_likely_compatibility
    if matches_host_os?
      @datastore['rhost'] = @host.address
    else
      @missing << :os_match
    end

    if @mod.session_types
      @required << :session

      if @host.sessions.alive.none? { |sess| matches_session?(sess) }
        @missing << :session
      end
    end

    if @mod.post_auth?
      unless @mod.default_cred? || have_service_cred? || have_datastore_cred?
        missing << :credential
      end
    end
  end

  def matches_session?(session)
    !!@mod.session_types&.include?(session.type)
  end

  def required_sessions_list
    return "" unless @mod.session_types

    @mod.session_types.join(' or ')
  end

  def have_service_cred?
    @available_creds.any?
  end

  def have_datastore_cred?
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
