# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for reporting data to the DB
#
###

module Auxiliary::Report

  # This method is responsible for creation {Metasploit::Credential::Core} objects
  # and all sub-objects that it is dependent upon.
  #
  # @option opts [Symbol] :origin_type The Origin type we are trying to create
  # @option opts [String] :address The address of the {Mdm::Host} to link this Origin to
  # @option opts [Fixnum] :port The port number of the {Mdm::Service} to link this Origin to
  # @option opts [String] :service_name The service name to use for the {Mdm::Service}
  # @option opts [String] :protocol The protocol type of the {Mdm::Service} to link this Origin to
  # @option opts [String] :module_fullname The fullname of the Metasploit Module to link this Origin to
  # @option opts [Fixnum] :workspace_id The ID of the {Mdm::Workspace} to use for the {Mdm::Host}
  # @option opts [Fixnum] :task_id The ID of the {Mdm::Task} to link this Origin to
  # @option opts [String] :filename The filename of the file that was imported
  # @option opts [Fixnum] :user_id The ID of the {Mdm::User} to link this Origin to
  # @option opts [Fixnum] :session_id The ID of the {Mdm::Session} to link this Origin to
  # @option opts [String] :post_reference_name The reference name of the Metasploit Post module to link the origin to
  # @option opts [String] :private_data The actual data for the private (e.g. password, hash, key etc)
  # @option opts [Symbol] :private_type The type of {Metasploit::Credential::Private} to create
  # @option opts [String] :username The username to use for the {Metasploit::Credential::Public}
  # @raise [KeyError] if a required option is missing
  # @raise [ArgumentError] if an invalid :private_type is specified
  # @raise [ArgumentError] if an invalid :origin_type is specified
  # @return [NilClass] if there is no active database connection
  # @return [Metasploit::Credential::Core]
  # @example Reporting a Bruteforced Credential
  #     create_credential(
  #       origin_type: :service,
  #       address: '192.168.1.100',
  #       port: 445,
  #       service_name: 'smb',
  #       protocol: 'tcp',
  #       module_fullname: 'auxiliary/scanner/smb/smb_login',
  #       workspace_id: myworkspace.id,
  #       private_data: 'password1',
  #       private_type: :password,
  #       username: 'Administrator'
  #     )
  def create_credential(opts={})
    return nil unless framework.db.active
    origin = create_credential_origin(opts)

    core_opts = {
        origin: origin,
        workspace_id: opts.fetch(:workspace_id)
    }

    if opts.has_key?(:realm_key) && opts.has_key?(:realm_value)
      core_opts[:realm] = create_credential_realm(opts)
    end

    if opts.has_key?(:private_type) && opts.has_key?(:private_data)
      core_opts[:private] = create_credential_private(opts)
    end

    if opts.has_key?(:username)
      core_opts[:public] = create_credential_public(opts)
    end

    create_credential_core(core_opts)
  end

  # This method is responsible for creating {Metasploit::Credential::Core} objects.
  #
  # @option opts [Metasploit::Credential::Origin] :origin The origin object to tie the core to
  # @option opts [Metasploit::Credential::Public] :public The {Metasploit::Credential::Public} component
  # @option opts [Metasploit::Credential::Private] :private The {Metasploit::Credential::Private} component
  # @option opts [Fixnum] :workspace_id The ID of the {Mdm::Workspace} to tie the Core to
  # @return [NilClass] if there is no active database connection
  # @return [Metasploit::Credential::Core]
  def create_credential_core(opts={})
    return nil unless framework.db.active
    origin       = opts.fetch(:origin)
    workspace_id = opts.fetch(:workspace_id)

    if opts[:private]
      private_id = opts[:private].id
    else
      private_id = nil
    end

    if opts[:public]
      public_id = opts[:public].id
    else
      public_id = nil
    end

    if opts[:realm]
      realm_id = opts[:realm].id
    else
      realm_id = nil
    end

    core = Metasploit::Credential::Core.where(private_id: private_id, public_id: public_id, realm_id: realm_id, workspace_id: workspace_id).first_or_create
    if core.origin_id.nil?
      core.origin = origin
    end
    core.save!
    core
  end

  # This method is responsible for creating a {Metasploit::Credential::Login} object
  # which ties a {Metasploit::Credential::Core} to the {Mdm::Service} it is a valid
  # credential for.
  #
  # @option opts [String] :access_level The access level to assign to this login if we know it
  # @option opts [String] :address The address of the {Mdm::Host} to link this Login to
  # @option opts [DateTime] :last_attempted_at The last time this Login was attempted
  # @option opts [Metasploit::Credential::Core] :core The {Metasploit::Credential::Core} to link this login to
  # @option opts [Fixnum] :port The port number of the {Mdm::Service} to link this Login to
  # @option opts [String] :service_name The service name to use for the {Mdm::Service}
  # @option opts [String] :status The status for the Login object
  # @option opts [String] :protocol The protocol type of the {Mdm::Service} to link this Login to
  # @option opts [Fixnum] :workspace_id The ID of the {Mdm::Workspace} to use for the {Mdm::Host}
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no active database connection
  # @return [Metasploit::Credential::Login]
  def create_credential_login(opts)
    return nil unless framework.db.active
    access_level       = opts.fetch(:access_level, nil)
    core               = opts.fetch(:core)
    last_attempted_at  = opts.fetch(:last_attempted_at, nil)
    status             = opts.fetch(:status)

    service_object = create_credential_service(opts)
    login_object = Metasploit::Credential::Login.where(core_id: core.id, service_id: service_object.id).first_or_create

    login_object.access_level      = access_level if access_level
    login_object.last_attempted_at = last_attempted_at if last_attempted_at
    login_object.status            = status
    login_object.save!
    login_object
  end

  # This method is responsible for the creation of {Metasploit::Credential::Private} objects.
  # It will create the correct subclass based on the type.
  #
  # @option opts [String] :private_data The actual data for the private (e.g. password, hash, key etc)
  # @option opts [Symbol] :private_type The type of {Metasploit::Credential::Private} to create
  # @raise [ArgumentError] if a valid type is not supplied
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no active database connection
  # @return [Metasploit::Credential::Password] if the private_type was :password
  # @return [Metasploit::Credential::SSHKey] if the private_type was :ssh_key
  # @return [Metasploit::Credential::NTLMHash] if the private_type was :ntlm_hash
  # @return [Metasploit::Credential::NonreplayableHash] if the private_type was :nonreplayable_hash
  def create_credential_private(opts={})
    return nil unless framework.db.active
    private_data = opts.fetch(:private_data)
    private_type = opts.fetch(:private_type)

    case private_type
      when :password
        private_object = Metasploit::Credential::Password.where(data: private_data).first_or_create
      when :ssh_key
        private_object = Metasploit::Credential::SSHKey.where(data: private_data).first_or_create
      when :ntlm_hash
        private_object = Metasploit::Credential::NTLMHash.where(data: private_data).first_or_create
      when :nonreplayable_hash
        private_object = Metasploit::Credential::NonreplayableHash.where(data: private_data).first_or_create
      else
        raise ArgumentError, "Invalid Private type: #{private_type}"
    end
    private_object.save!
    private_object
  end

  # This method is responsible for the creation of {Metasploit::Credential::Public} objects.
  #
  # @option opts [String] :username The username to use for the {Metasploit::Credential::Public}
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no active database connection
  # @return [Metasploit::Credential::Public]
  def create_credential_public(opts={})
    return nil unless framework.db.active
    username = opts.fetch(:username)

    public_object = Metasploit::Credential::Public.where(username: username).first_or_create
    public_object.save!
    public_object
  end

  # This method is responsible for creating the {Metasploit::Credential::Realm} objects
  # that may be required.
  #
  # @option opts [String] :realm_key The type of Realm this is (e.g. 'Active Directory Domain')
  # @option opts [String] :realm_value The actual Realm name (e.g. contosso)
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no active database connection
  # @return [Metasploit::Credential::Realm] if it successfully creates or finds the object
  def create_credential_realm(opts={})
    return nil unless framework.db.active
    realm_key   = opts.fetch(:realm_key)
    realm_value = opts.fetch(:realm_value)

    realm_object = Metasploit::Credential::Realm.where(key: realm_key, value: realm_value).first_or_create
    realm_object.save!
    realm_object
  end

  # This method is responsible for creating the various Credential::Origin objects.
  # It takes a key for the Origin type and delegates to the correct sub-method.
  #
  # @option opts [Symbol] :origin_type The Origin type we are trying to create
  # @option opts [String] :address The address of the {Mdm::Host} to link this Origin to
  # @option opts [Fixnum] :port The port number of the {Mdm::Service} to link this Origin to
  # @option opts [String] :service_name The service name to use for the {Mdm::Service}
  # @option opts [String] :protocol The protocol type of the {Mdm::Service} to link this Origin to
  # @option opts [String] :module_fullname The fullname of the Metasploit Module to link this Origin to
  # @option opts [Fixnum] :workspace_id The ID of the {Mdm::Workspace} to use for the {Mdm::Host}
  # @option opts [Fixnum] :task_id The ID of the {Mdm::Task} to link this Origin to
  # @option opts [String] :filename The filename of the file that was imported
  # @option opts [Fixnum] :user_id The ID of the {Mdm::User} to link this Origin to
  # @option opts [Fixnum] :session_id The ID of the {Mdm::Session} to link this Origin to
  # @option opts [String] :post_reference_name The reference name of the Metasploit Post module to link the origin to
  # @raise [ArgumentError] if an invalid origin_type was provided
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::Manual] if :origin_type was :manual
  # @return [Metasploit::Credential::Origin::Import] if :origin_type was :import
  # @return [Metasploit::Credential::Origin::Service] if :origin_type was :service
  # @return [Metasploit::Credential::Origin::Session] if :origin_type was :session
  def create_credential_origin(opts={})
    return nil unless framework.db.active
    case opts[:origin_type]
      when :import
        create_credential_origin_import(opts)
      when :manual
        create_credential_origin_manual(opts)
      when :service
        create_credential_origin_service(opts)
      when :session
        create_credential_origin_session(opts)
      else
        raise ArgumentError, "Unknown Origin Type #{opts[:origin_type]}"
    end
  end

  # This method is responsible for creating {Metasploit::Credential::Origin::Import} objects.
  #
  # @option opts [Fixnum] :task_id The ID of the {Mdm::Task} to link this Origin to
  # @option opts [String] :filename The filename of the file that was imported
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::Manual] The created {Metasploit::Credential::Origin::Import} object
  def create_credential_origin_import(opts={})
    return nil unless framework.db.active
    task_id  = opts.fetch(:task_id)
    filename = opts.fetch(:filename)

    origin_object = Metasploit::Credential::Origin::Import.where(filename: filename, task_id: task_id).first_or_create
    origin_object.save!
    origin_object
  end

  # This method is responsible for creating {Metasploit::Credential::Origin::Manual} objects.
  #
  # @option opts [Fixnum] :user_id The ID of the {Mdm::User} to link this Origin to
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::Manual] The created {Metasploit::Credential::Origin::Manual} object
  def create_credential_origin_manual(opts={})
    return nil unless framework.db.active
    user_id = opts.fetch(:user_id)

    origin_object = Metasploit::Credential::Origin::Manual.where(user_id: user_id).first_or_create
    origin_object.save!
    origin_object
  end

  # This method is responsible for creating {Metasploit::Credential::Origin::Service} objects.
  # If there is not a matching {Mdm::Host} it will create it. If there is not a matching
  # {Mdm::Service} it will create that too.
  #
  # @option opts [String] :address The address of the {Mdm::Host} to link this Origin to
  # @option opts [Fixnum] :port The port number of the {Mdm::Service} to link this Origin to
  # @option opts [String] :service_name The service name to use for the {Mdm::Service}
  # @option opts [String] :protocol The protocol type of the {Mdm::Service} to link this Origin to
  # @option opts [String] :module_fullname The fullname of the Metasploit Module to link this Origin to
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::Service] The created {Metasploit::Credential::Origin::Service} object
  def create_credential_origin_service(opts={})
    return nil unless framework.db.active
    module_fullname  = opts.fetch(:module_fullname)

    service_object = create_credential_service(opts)

    origin_object = Metasploit::Credential::Origin::Service.where(service_id: service_object.id, module_full_name: module_fullname).first_or_create
    origin_object.save!
    origin_object
  end

  # This method is responsible for creating {Metasploit::Credential::Origin::Session} objects.
  #
  # @option opts [Fixnum] :session_id The ID of the {Mdm::Session} to link this Origin to
  # @option opts [String] :post_reference_name The reference name of the Metasploit Post module to link the origin to
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::Session] The created {Metasploit::Credential::Origin::Session} object
  def create_credential_origin_session(opts={})
    return nil unless framework.db.active
    session_id           = opts.fetch(:session_id)
    post_reference_name  = opts.fetch(:post_reference_name)

    origin_object = Metasploit::Credential::Origin::Session.where(session_id: session_id, post_reference_name: post_reference_name).first_or_create
    origin_object.save!
    origin_object
  end

  # This method is responsible for creating a barebones {Mdm::Service} object
  # for use by Credential object creation.
  #
  # @option opts [String] :address The address of the {Mdm::Host}
  # @option opts [Fixnum] :port The port number of the {Mdm::Service}
  # @option opts [String] :service_name The service name to use for the {Mdm::Service}
  # @option opts [String] :protocol The protocol type of the {Mdm::Service}
  # @option opts [Fixnum] :workspace_id The ID of the {Mdm::Workspace} to use for the {Mdm::Host}
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Mdm::Service]
  def create_credential_service(opts={})
    return nil unless framework.db.active
    address          = opts.fetch(:address)
    port             = opts.fetch(:port)
    service_name     = opts.fetch(:service_name)
    protocol         = opts.fetch(:protocol)
    workspace_id     = opts.fetch(:workspace_id)

    # Find or create the host object we need
    host_object    = Mdm::Host.where(address: address, workspace_id: workspace_id).first_or_create
    host_object.save!

    # Next we find or create the Service object we need
    service_object = Mdm::Service.where(host_id: host_object.id, port: port, proto: protocol).first_or_create
    service_object.name = service_name
    service_object.save!
    service_object
  end


  # Shortcut method for detecting when the DB is active
  def db
    framework.db.active
  end

  def myworkspace
    @myworkspace = framework.db.find_workspace(self.workspace)
  end

  def mytask
    if self[:task]
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
  #
  # opts must contain
  #	:host      the address of the client connecting
  #	:ua_string a string that uniquely identifies this client
  # opts can contain
  #	:ua_name a brief identifier for the client, e.g. "Firefox"
  #	:ua_ver  the version number of the client, e.g. "3.0.11"
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

  def report_auth_info(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_auth_info(opts)
  end

  def report_vuln(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_vuln(opts)
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
    when "text/plain"
      ext = "txt"
    end
    # This method is available even if there is no database, don't bother checking
    host = framework.db.normalize_host(host)

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
  # +filenmae+ is the local file name.
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

    # Split by path seperator
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
    cred_host = myworkspace.hosts.find_by_address(cred_opts[:host])
    unless opts[:port]
      possible_services = myworkspace.services.find_all_by_host_id_and_name(cred_host[:id],cred_opts[:sname])
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
      session = myworkspace.sessions.find_all_by_local_id(opts[:collect_session]).last
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

