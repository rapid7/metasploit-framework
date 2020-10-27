# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for reporting data to the DB
#
###

module Auxiliary::Report
  extend Metasploit::Framework::Require

  optionally_include_metasploit_credential_creation

  def db_warning_given?
    if @warning_issued
      true
    else
      @warning_issued = true
      false
    end
  end

  def create_cracked_credential(opts={})
    if active_db?
      opts = { :task_id => mytask.id }.merge(opts) if mytask
      framework.db.create_cracked_credential(opts)
    elsif !db_warning_given?
      vprint_warning('No active DB -- Credential data will not be saved!')
    end
  end

  def create_credential(opts={})
    if active_db?
      opts = { :task_id => mytask.id }.merge(opts) if mytask
      framework.db.create_credential(opts)
    elsif !db_warning_given?
      vprint_warning('No active DB -- Credential data will not be saved!')
    end
  end

  def create_credential_login(opts={})
    if active_db?
      opts = { :task_id => mytask.id }.merge(opts) if mytask
      framework.db.create_credential_login(opts)
    elsif !db_warning_given?
      vprint_warning('No active DB -- Credential data will not be saved!')
    end
  end

  def create_credential_and_login(opts={})
    if active_db?
      opts = { :task_id => mytask.id }.merge(opts) if mytask
      framework.db.create_credential_and_login(opts)
    elsif !db_warning_given?
      vprint_warning('No active DB -- Credential data will not be saved!')
    end
  end

  def invalidate_login(opts={})
    if active_db?
      opts = { :task_id => mytask.id }.merge(opts) if mytask
      framework.db.invalidate_login(opts)
    elsif !db_warning_given?
      vprint_warning('No active DB -- Credential data will not be saved!')
    end
  end

  # This method overrides the method from Metasploit::Credential to check for an active db
  def active_db?
    framework.db.active
  end

  # Shortcut method for detecting when the DB is active
  def db
    framework.db.active
  end

  def myworkspace
    @myworkspace = framework.db.find_workspace(self.workspace)
  end

  # This method safely get the workspace ID. It handles if the db is not active
  #
  # @return [NilClass] if there is no DB connection
  # @return [Integer] the ID of the current Mdm::Workspace
  def myworkspace_id
    if framework.db.active
      myworkspace.id
    else
      nil
    end
  end

  def mytask
    if self.respond_to?(:[]) && self[:task]
      return self[:task].record
    elsif @task && @task.class == Mdm::Task
      return @task
    else
      return nil
    end
  end

  def inside_workspace_boundary?(ip)
    return true if not framework.db.active
    allowed = myworkspace.allow_actions_on?(ip)
    return allowed
  end



  #
  # Report a host's liveness and attributes such as operating system and service pack
  #
  # opts must contain :host, which is an IP address identifying the host
  # you're reporting about
  #
  # See data/sql/*.sql and lib/msf/core/db.rb for more info
  #
  def report_host(opts)
    return if not db
    opts = {
      :workspace => myworkspace,
      :task => mytask
    }.merge(opts)
    framework.db.report_host(opts)
  end

  def get_host(opts)
    return if not db
    opts = {:workspace => myworkspace}.merge(opts)
    framework.db.get_host(opts)
  end

  #
  # Report a client connection
  # @param opts [Hash] report client information based on user-agent
  # @option opts [String] :host the address of the client connecting
  # @option opts [String] :ua_string a string that uniquely identifies this client
  # @option opts [String] :ua_name a brief identifier for the client, e.g. "Firefox"
  # @option opts [String] :ua_ver  the version number of the client, e.g. "3.0.11"
  #
  def report_client(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_client(opts)
  end

  def get_client(opts={})
    return if not db
    opts = {:workspace => myworkspace}.merge(opts)
    framework.db.get_client(opts)
  end

  #
  # Report detection of a service
  #
  def report_service(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_service(opts)
  end

  def report_note(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_note(opts)
  end

  # This Legacy method is responsible for creating credentials from data supplied
  # by a module. This method is deprecated and the new Metasploit::Credential methods
  # should be used directly instead.
  #
  # @param opts [Hash] the option hash
  # @option opts [String] :host the address of the host (also takes a Mdm::Host)
  # @option opts [Integer] :port the port of the connected service
  # @option opts [Mdm::Service] :service an optional Service object to build the cred for
  # @option opts [String] :type What type of private credential this is (e.g. "password", "hash", "ssh_key")
  # @option opts [String] :proto Which transport protocol the service uses
  # @option opts [String] :sname The 'name' of the service
  # @option opts [String] :user The username for the cred
  # @option opts [String] :pass The private part of the credential (e.g. password)
  def report_auth_info(opts={})
    print_warning("*** #{self.fullname} is still calling the deprecated report_auth_info method! This needs to be updated!")
    print_warning('*** For detailed information about LoginScanners and the Credentials objects see:')
    print_warning('     https://github.com/rapid7/metasploit-framework/wiki/Creating-Metasploit-Framework-LoginScanners')
    print_warning('     https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-HTTP-LoginScanner-Module')
    print_warning('*** For examples of modules converted to just report credentials without report_auth_info, see:')
    print_warning('     https://github.com/rapid7/metasploit-framework/pull/5376')
    print_warning('     https://github.com/rapid7/metasploit-framework/pull/5377')
    return unless db
    raise ArgumentError.new("Missing required option :host") if opts[:host].nil?
    raise ArgumentError.new("Missing required option :port") if (opts[:port].nil? and opts[:service].nil?)

    if opts[:host].kind_of?(::Mdm::Host)
      host = opts[:host].address
    else
      host = opts[:host]
    end

    type = :password
    case opts[:type]
      when "password"
        type = :password
      when "hash"
        type = :nonreplayable_hash
      when "ssh_key"
        type = :ssh_key
    end

    case opts[:proto]
      when "tcp"
        proto = "tcp"
      when "udp"
        proto = "udp"
      else
        proto = "tcp"
    end

    if opts[:service] && opts[:service].kind_of?(Mdm::Service)
      port         = opts[:service].port
      proto        = opts[:service].proto
      service_name = opts[:service].name
      host         = opts[:service].host.address
    else
      port         = opts.fetch(:port)
      service_name = opts.fetch(:sname, nil)
    end

    username = opts.fetch(:user, nil)
    private  = opts.fetch(:pass, nil)

    service_data = {
      address: host,
      port: port,
      service_name: service_name,
      protocol: proto,
      workspace_id: myworkspace_id
    }

    if self.type == "post"
      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: self.refname
      }
    else
      credential_data = {
        origin_type: :service,
        module_fullname: self.fullname
      }
      credential_data.merge!(service_data)
    end

    unless private.nil?
      credential_data[:private_type] = type
      credential_data[:private_data] = private
    end

    unless username.nil?
      credential_data[:username] = username
    end

    credential_core = create_credential(credential_data)

    login_data ={
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }
    login_data.merge!(service_data)
    create_credential_login(login_data)
  end

  def report_vuln(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    vuln = framework.db.report_vuln(opts)

    # add vuln attempt audit details here during report

    timestamp  = opts[:timestamp]
    username   = opts[:username]
    mname      = self.fullname # use module name when reporting attempt for correlation

    # report_vuln is only called in an identified case, consider setting value reported here
    attempt_info = {
        :vuln_id      => vuln.id,
        :attempted_at => timestamp || Time.now.utc,
        :exploited    => false,
        :fail_detail  => 'vulnerability identified',
        :fail_reason  => 'Untried', # Mdm::VulnAttempt::Status::UNTRIED, avoiding direct dependency on Mdm, used elsewhere in this module
        :module       => mname,
        :username     => username  || "unknown",
    }

    # TODO: figure out what opts are required and why the above logic doesn't match that of the db_manager method
    framework.db.report_vuln_attempt(vuln, attempt_info)

    vuln
  end

  # This will simply log a deprecation warning, since report_exploit()
  # is no longer implemented.
  def report_exploit(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_exploit(opts)
  end

  def report_loot(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_loot(opts)
  end

  def report_web_site(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_web_site(opts)
  end

  def report_web_page(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_web_page(opts)
  end

  def report_web_form(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_web_form(opts)
  end

  def report_web_vuln(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_web_vuln(opts)
  end

  #
  # Store some data stolen from a session as a file
  #
  # Also stores metadata about the file in the database when available
  # +ltype+ is an OID-style loot type, e.g. "cisco.ios.config".  Ignored when
  # no database is connected.
  #
  # +ctype+ is the Content-Type, e.g. "text/plain".  Affects the extension
  # the file will be saved with.
  #
  # +host+ can be an String address or a Session object
  #
  # +data+ is the actual contents of the file
  #
  # +filename+ and +info+ are only stored as metadata, and therefore both are
  # ignored if there is no database
  #
  def store_loot(ltype, ctype, host, data, filename=nil, info=nil, service=nil)
    if ! ::File.directory?(Msf::Config.loot_directory)
      FileUtils.mkdir_p(Msf::Config.loot_directory)
    end

    ext = 'bin'
    if filename
      parts = filename.to_s.split('.')
      if parts.length > 1 and parts[-1].length < 4
        ext = parts[-1]
      end
    end

    case ctype
    when /^text\/[\w\.]+$/
      ext = "txt"
    end
    # This method is available even if there is no database, don't bother checking
    host = Msf::Util::Host.normalize_host(host)

    ws = (db ? myworkspace.name[0,16] : 'default')
    name =
      Time.now.strftime("%Y%m%d%H%M%S") + "_" + ws + "_" +
      (host || 'unknown') + '_' + ltype[0,16] + '_' +
      Rex::Text.rand_text_numeric(6) + '.' + ext

    name.gsub!(/[^a-z0-9\.\_]+/i, '')

    path = File.join(Msf::Config.loot_directory, name)
    full_path = ::File.expand_path(path)
    File.open(full_path, "wb") do |fd|
      fd.write(data)
    end

    if (db)
      # If we have a database we need to store it with all the available
      # metadata.
      conf = {}
      conf[:host] = host if host
      conf[:type] = ltype
      conf[:content_type] = ctype
      conf[:path] = full_path
      conf[:workspace] = myworkspace
      conf[:name] = filename if filename
      conf[:info] = info if info
      conf[:data] = data if data

      if service and service.kind_of?(::Mdm::Service)
        conf[:service] = service if service
      end

      framework.db.report_loot(conf)
    end

    return full_path.dup
  end

  #
  # Store some locally-generated data as a file, similiar to store_loot.
  # Sometimes useful for keeping artifacts of an exploit or auxiliary
  # module, such as files from fileformat exploits. (TODO: actually
  # implement this on file format modules.)
  #
  # +filename+ is the local file name.
  #
  # +data+ is the actual contents of the file
  #
  # Also stores metadata about the file in the database when available.
  # +ltype+ is an OID-style loot type, e.g. "cisco.ios.config".  Ignored when
  # no database is connected.
  #
  # +ctype+ is the Content-Type, e.g. "text/plain". Ignored when no database
  # is connected.
  #
  def store_local(ltype=nil, ctype=nil, data=nil, filename=nil)
    if ! ::File.directory?(Msf::Config.local_directory)
      FileUtils.mkdir_p(Msf::Config.local_directory)
    end

    # Split by fname an extension
    if filename and not filename.empty?
      if filename =~ /(.*)\.(.*)/
        ext = $2
        fname = $1
      else
        fname = filename
      end
    else
      fname = ctype || "local_#{Time.now.utc.to_i}"
    end

    # Split by path separator
    fname = ::File.split(fname).last

    case ctype # Probably could use more cases
    when "text/plain"
      ext ||= "txt"
    when "text/xml"
      ext ||= "xml"
    when "text/html"
      ext ||= "html"
    when "application/pdf"
      ext ||= "pdf"
    else
      ext ||= "bin"
    end

    fname.gsub!(/[^a-z0-9\.\_\-]+/i, '')
    fname << ".#{ext}"

    ltype.gsub!(/[^a-z0-9\.\_\-]+/i, '')

    path = File.join(Msf::Config.local_directory, fname)
    full_path = ::File.expand_path(path)
    File.open(full_path, "wb") { |fd| fd.write(data) }

    # This will probably evolve into a new database table
    report_note(
      :data => full_path.dup,
      :type => "#{ltype}.localpath"
    )

    return full_path.dup
  end

  # Takes a credential from a script (shell or meterpreter), and
  # sources it correctly to the originating user account or
  # session. Note that the passed-in session ID should be the
  # Session.local_id, which will be correlated with the Session.id
  def store_cred(opts={})
    if [opts[:port],opts[:sname]].compact.empty?
      raise ArgumentError, "Missing option: :sname or :port"
    end
    cred_opts = opts
    cred_opts = opts.merge(:workspace => myworkspace)
    cred_opts = { :task_id => mytask.id }.merge(cred_opts) if mytask
    cred_host = myworkspace.hosts.find_by_address(cred_opts[:host])
    unless opts[:port]
      possible_services = myworkspace.services.where(host_id: cred_host[:id], name: cred_opts[:sname])
      case possible_services.size
      when 0
        case cred_opts[:sname].downcase
        when "smb"
          cred_opts[:port] = 445
        when "ssh"
          cred_opts[:port] = 22
        when "telnet"
          cred_opts[:port] = 23
        when "snmp"
          cred_opts[:port] = 161
          cred_opts[:proto] = "udp"
        else
          raise ArgumentError, "No matching :sname found to store this cred."
        end
      when 1
        cred_opts[:port] = possible_services.first[:port]
      else # SMB should prefer 445. Everyone else, just take the first hit.
        if (cred_opts[:sname].downcase == "smb") && possible_services.map {|x| x[:port]}.include?(445)
          cred_opts[:port] = 445
        elsif (cred_opts[:sname].downcase == "ssh") && possible_services.map {|x| x[:port]}.include?(22)
          cred_opts[:port] = 22
        else
          cred_opts[:port] = possible_services.first[:port]
        end
      end
    end
    if opts[:collect_user]
      cred_service = cred_host.services.find_by_host_id(cred_host[:id])
      myworkspace.creds.sort {|a,b| a.created_at.to_f}.each do |cred|
        if(cred.user.downcase == opts[:collect_user].downcase &&
           cred.pass == opts[:collect_pass]
          )
          cred_opts[:source_id] ||= cred.id
          cred_opts[:source_type] ||= cred_opts[:collect_type]
          break
        end
      end
    end
    if opts[:collect_session]
      session = myworkspace.sessions.where(local_id: opts[:collect_session]).last
      if !session.nil?
        cred_opts[:source_id] = session.id
        cred_opts[:source_type] = "exploit"
      end
    end
    print_status "Collecting #{cred_opts[:user]}:#{cred_opts[:pass]}"
    framework.db.report_auth_info(cred_opts)
  end



end
end

