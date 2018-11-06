require 'rex/socket'

# Implements a set of "convenience methods" for creating credentials and related portions of the object graph.  Creates
# {Metasploit::Credential::Core} objects and their attendant relationships as well as {Metasploit::Credential::Login}
# objects and their attendant `Mdm::Host` and `Mdm::Service` objects.
module Metasploit::Credential::Creation

  # Returns true if ActiveRecord has an active database connection, false otherwise.
  # @return [Boolean]
  def active_db?
    ActiveRecord::Base.connected?
  end

  # This method takes a few simple parameters and creates a new username/password
  # credential that was obtained by cracking a hash. It reuses the relevant
  # components form the originating {Metasploit::Credential::Core} and builds new
  # {Metasploit::Credential::Login} objects based on the ones attached to the originating
  # {Metasploit::Credential::Core}
  #
  # @option opts [String] :username the username to find or create the {Metasploit::Credential::Public} from
  # @option opts [String] :password the password to find or create the {Metasploit::Credential::Password} from
  # @option opts [Fixnum] :core_id the id for the originating {Metasploit::Credential::Core}
  def create_cracked_credential(opts={})
    return nil unless active_db?

    if self.respond_to?(:[]) and self[:task]
      opts[:task_id] ||= self[:task].record.id
    end

    username = opts.fetch(:username)
    password = opts.fetch(:password)
    core_id  = opts.fetch(:core_id)

    private  = nil
    public   = nil
    old_core = nil
    old_realm_id = nil

    retry_transaction do
      private  = Metasploit::Credential::Password.where(data: password).first_or_create!
      public   = Metasploit::Credential::Public.where(username: username).first_or_create!
      old_core = Metasploit::Credential::Core.find(core_id)
      old_realm_id = old_core.realm.id if old_core.realm
    end

    core = nil

    retry_transaction do
      core = Metasploit::Credential::Core.where(public_id: public.id, private_id: private.id, realm_id: old_realm_id, workspace_id: old_core.workspace_id).first_or_initialize
      if core.origin_id.nil?
        origin      = Metasploit::Credential::Origin::CrackedPassword.where(metasploit_credential_core_id: core_id).first_or_create!
        core.origin = origin
      end
      if opts[:task_id]
        core.tasks << Mdm::Task.find(opts[:task_id])
      end
      core.save!
    end

    old_core.logins.each do |login|
      service_id = login.service_id
      new_login = Metasploit::Credential::Login.where(core_id: core.id, service_id: service_id).first_or_initialize
      if new_login.status.blank?
        new_login.status =  Metasploit::Model::Login::Status::UNTRIED
      end
      new_login.save!
    end
    core
  end


  # This method is responsible for creation {Metasploit::Credential::Core} objects
  # and all sub-objects that it is dependent upon.
  #
  # @option opts [String] :jtr_format The format for John the ripper to use to try and crack this
  # @option opts [Symbol] :origin_type The Origin type we are trying to create
  # @option opts [String] :address The address of the `Mdm::Host` to link this Origin to
  # @option opts [Fixnum] :port The port number of the `Mdm::Service` to link this Origin to
  # @option opts [String] :service_name The service name to use for the `Mdm::Service`
  # @option opts [String] :protocol The protocol type of the `Mdm::Service` to link this Origin to
  # @option opts [String] :module_fullname The fullname of the Metasploit Module to link this Origin to
  # @option opts [Fixnum] :workspace_id The ID of the `Mdm::Workspace` to use for the `Mdm::Host`
  # @option opts [Fixnum] :task_id The ID of the `Mdm::Task` to link this Origin and Core to
  # @option opts [String] :filename The filename of the file that was imported
  # @option opts [Fixnum] :user_id The ID of the `Mdm::User` to link this Origin to
  # @option opts [Fixnum] :session_id The ID of the `Mdm::Session` to link this Origin to
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
    return nil unless active_db?

    if self.respond_to?(:[]) and self[:task]
      opts[:task_id] ||= self[:task].record.id
    end

    if opts[:origin]
      origin = opts[:origin]
    else
      origin = create_credential_origin(opts)
    end
    return nil if origin.nil?

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

    if opts.has_key?(:task_id)
      core_opts[:task_id] = opts[:task_id]
    end

    create_credential_core(core_opts)
  end

  # This method is responsible for creation {Metasploit::Credential::Core} and
  # {Metasploit::Credential::Login}.
  # This method is responsible for creating a {Metasploit::Credential::Login} object
  # which ties a {Metasploit::Credential::Core} to the `Mdm::Service` it is a valid
  # credential for.
  #
  # NOTE: for origin_type: service it must be the same service your going to create a login for.
  #
  # {Metasploit::Credential::Core} options
  # @option opts [String] :jtr_format The format for John the ripper to use to try and crack this
  # @option opts [Symbol] :origin_type The Origin type we are trying to create
  # @option opts [String] :address The address of the `Mdm::Host` to link this Origin to
  # @option opts [Fixnum] :port The port number of the `Mdm::Service` to link this Origin to
  # @option opts [String] :service_name The service name to use for the `Mdm::Service`
  # @option opts [String] :protocol The protocol type of the `Mdm::Service` to link this Origin to
  # @option opts [String] :module_fullname The fullname of the Metasploit Module to link this Origin to
  # @option opts [Fixnum] :workspace_id The ID of the `Mdm::Workspace` to use for the `Mdm::Host`
  # @option opts [Fixnum] :task_id The ID of the `Mdm::Task` to link this Origin and Core to
  # @option opts [String] :filename The filename of the file that was imported
  # @option opts [Fixnum] :user_id The ID of the `Mdm::User` to link this Origin to
  # @option opts [Fixnum] :session_id The ID of the `Mdm::Session` to link this Origin to
  # @option opts [String] :post_reference_name The reference name of the Metasploit Post module to link the origin to
  # @option opts [String] :private_data The actual data for the private (e.g. password, hash, key etc)
  # @option opts [Symbol] :private_type The type of {Metasploit::Credential::Private} to create
  # {Metasploit::Credential::Login}
  # @option opts [String] :access_level The access level to assign to this login if we know it
  # @option opts [String] :status The status for the Login object
  # @raise [KeyError] if a required option is missing
  # @raise [ArgumentError] if an invalid :private_type is specified
  # @raise [ArgumentError] if an invalid :origin_type is specified
  # @return [NilClass] if there is no active database connection
  # @return [Metasploit::Credential::Core]
  # @example Reporting a Bruteforced Credential and Login
  #     create_credential_and_login(
  #       origin_type: :service,
  #       address: '192.168.1.100',
  #       port: 445,
  #       service_name: 'smb',
  #       protocol: 'tcp',
  #       module_fullname: 'auxiliary/scanner/smb/smb_login',
  #       workspace_id: myworkspace.id,
  #       private_data: 'password1',
  #       private_type: :password,
  #       username: 'Administrator',
  #       service_name: 'smb',
  #       status: status: Metasploit::Model::Login::Status::UNTRIED
  #     )
  def create_credential_and_login(opts={})
    return nil unless active_db?

    if self.respond_to?(:[]) and self[:task]
      opts[:task_id] ||= self[:task].record.id
    end

    core               = opts.fetch(:core, create_credential(opts))
    access_level       = opts.fetch(:access_level, nil)
    last_attempted_at  = opts.fetch(:last_attempted_at, nil)
    status             = opts.fetch(:status, Metasploit::Model::Login::Status::UNTRIED)

    login_object = nil
    retry_transaction do
      service_object = create_credential_service(opts)
      return nil if service_object.nil?
      login_object = Metasploit::Credential::Login.where(core_id: core.id, service_id: service_object.id).first_or_initialize

      if opts[:task_id]
        login_object.tasks << Mdm::Task.find(opts[:task_id])
      end

      login_object.access_level      = access_level if access_level
      login_object.last_attempted_at = last_attempted_at if last_attempted_at
      if status == Metasploit::Model::Login::Status::UNTRIED
        if login_object.last_attempted_at.nil?
          login_object.status = status
        end
      else
        login_object.status = status
      end
      login_object.save!
    end

    login_object
  end

  # This method is responsible for creating {Metasploit::Credential::Core} objects.
  #
  # @option opts [Metasploit::Credential::Origin] :origin The origin object to tie the core to
  # @option opts [Metasploit::Credential::Public] :public The {Metasploit::Credential::Public} component
  # @option opts [Metasploit::Credential::Private] :private The {Metasploit::Credential::Private} component
  # @option opts [Metasploit::Credential::Realm] :realm The {Metasploit::Credential::Realm} component
  # @option opts [Fixnum] :workspace_id The ID of the `Mdm::Workspace` to tie the Core to
  # @option opts [Fixnum] :task_id The ID of the `Mdm::Task` to link this Core to
  # @return [NilClass] if there is no active database connection
  # @return [Metasploit::Credential::Core]
  def create_credential_core(opts={})
    return nil unless active_db?

    if self.respond_to?(:[]) and self[:task]
      opts[:task_id] ||= self[:task].record.id
    end

    origin       = opts.fetch(:origin)
    workspace_id = opts.fetch(:workspace_id)

    private_id   = opts[:private].try(:id)
    public_id    = opts[:public].try(:id)
    realm_id     = opts[:realm].try(:id)

    core = nil
    retry_transaction do
      core = Metasploit::Credential::Core.where(private_id: private_id, public_id: public_id, realm_id: realm_id, workspace_id: workspace_id).first_or_initialize
      if core.origin_id.nil?
        core.origin = origin
      end
      if opts[:task_id]
        core.tasks << Mdm::Task.find(opts[:task_id])
      end
      core.save!
    end

    core
  end

  # This method is responsible for creating a {Metasploit::Credential::Login} object
  # which ties a {Metasploit::Credential::Core} to the `Mdm::Service` it is a valid
  # credential for.
  #
  # @option opts [String] :access_level The access level to assign to this login if we know it
  # @option opts [String] :address The address of the `Mdm::Host` to link this Login to
  # @option opts [DateTime] :last_attempted_at The last time this Login was attempted
  # @option opts [Metasploit::Credential::Core] :core The {Metasploit::Credential::Core} to link this login to
  # @option opts [Fixnum] :port The port number of the `Mdm::Service` to link this Login to
  # @option opts [String] :service_name The service name to use for the `Mdm::Service`
  # @option opts [String] :status The status for the Login object
  # @option opts [String] :protocol The protocol type of the `Mdm::Service` to link this Login to
  # @option opts [Fixnum] :workspace_id The ID of the `Mdm::Workspace` to use for the `Mdm::Host`
  # @option opts [Fixnum] :task_id The ID of the `Mdm::Task` to link this Login to
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no active database connection
  # @return [Metasploit::Credential::Login]
  def create_credential_login(opts={})
    return nil unless active_db?

    if self.respond_to?(:[]) and self[:task]
      opts[:task_id] ||= self[:task].record.id
    end

    core               = opts.fetch(:core)
    access_level       = opts.fetch(:access_level, nil)
    last_attempted_at  = opts.fetch(:last_attempted_at, nil)
    status             = opts.fetch(:status, Metasploit::Model::Login::Status::UNTRIED)

    login_object = nil
    retry_transaction do
      service_object = create_credential_service(opts)
      return nil if service_object.nil?
      login_object = Metasploit::Credential::Login.where(core_id: core.id, service_id: service_object.id).first_or_initialize

      if opts[:task_id]
        login_object.tasks << Mdm::Task.find(opts[:task_id])
      end

      login_object.access_level      = access_level if access_level
      login_object.last_attempted_at = last_attempted_at if last_attempted_at
      if status == Metasploit::Model::Login::Status::UNTRIED
        if login_object.last_attempted_at.nil?
          login_object.status = status
        end
      else
        login_object.status = status
      end
      login_object.save!
    end

    login_object
  end

  # This method is responsible for creating the various Credential::Origin objects.
  # It takes a key for the Origin type and delegates to the correct sub-method.
  #
  # @option opts [Symbol] :origin_type The Origin type we are trying to create
  # @option opts [String] :address The address of the `Mdm::Host` to link this Origin to
  # @option opts [Fixnum] :port The port number of the `Mdm::Service` to link this Origin to
  # @option opts [String] :service_name The service name to use for the `Mdm::Service`
  # @option opts [String] :protocol The protocol type of the `Mdm::Service` to link this Origin to
  # @option opts [String] :module_fullname The fullname of the Metasploit Module to link this Origin to
  # @option opts [Fixnum] :workspace_id The ID of the `Mdm::Workspace` to use for the `Mdm::Host`
  # @option opts [Fixnum] :task_id The ID of the `Mdm::Task` to link this Origin to
  # @option opts [String] :filename The filename of the file that was imported
  # @option opts [Fixnum] :user_id The ID of the `Mdm::User` to link this Origin to
  # @option opts [Fixnum] :session_id The ID of the `Mdm::Session` to link this Origin to
  # @option opts [String] :post_reference_name The reference name of the Metasploit Post module to link the origin to
  # @raise [ArgumentError] if an invalid origin_type was provided
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::Manual] if :origin_type was :manual
  # @return [Metasploit::Credential::Origin::Import] if :origin_type was :import
  # @return [Metasploit::Credential::Origin::Service] if :origin_type was :service
  # @return [Metasploit::Credential::Origin::Session] if :origin_type was :session
  def create_credential_origin(opts={})
    return nil unless active_db?
    case opts[:origin_type]
    when :cracked_password
      create_credential_origin_cracked_password(opts)
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

  # This method is responsible for creating {Metasploit::Credential::Origin::CrackedPassword} objects.
  # These are the origins that show that a password Credential was obtained by cracking a hash Credential
  # that previously existed in the database.
  #
  # @option opts [Fixnum] :originating_core_id The ID of the originating Credential core.
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::CrackedPassword] The created {Metasploit::Credential::Origin::CrackedPassword} object
  def create_credential_origin_cracked_password(opts={})
    return nil unless active_db?
    originating_core_id = opts.fetch(:originating_core_id)

    retry_transaction do
      Metasploit::Credential::Origin::CrackedPassword.where(metasploit_credential_core_id: originating_core_id ).first_or_create!
    end
  end

  # This method is responsible for creating {Metasploit::Credential::Origin::Import} objects.
  #
  # @option opts [String] :filename The filename of the file that was imported
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::Manual] The created {Metasploit::Credential::Origin::Import} object
  def create_credential_origin_import(opts={})
    return nil unless active_db?
    filename = opts.fetch(:filename)

    retry_transaction do
      Metasploit::Credential::Origin::Import.where(filename: filename).first_or_create!
    end
  end

  # This method is responsible for creating {Metasploit::Credential::Origin::Manual} objects.
  #
  # @option opts [Fixnum] :user_id The ID of the `Mdm::User` to link this Origin to
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::Manual] The created {Metasploit::Credential::Origin::Manual} object
  def create_credential_origin_manual(opts={})
    return nil unless active_db?
    user_id = opts.fetch(:user_id)

    retry_transaction do
      Metasploit::Credential::Origin::Manual.where(user_id: user_id).first_or_create!
    end
  end

  # This method is responsible for creating {Metasploit::Credential::Origin::Service} objects.
  # If there is not a matching `Mdm::Host` it will create it. If there is not a matching
  # `Mdm::Service` it will create that too.
  #
  # @option opts [String] :address The address of the `Mdm::Host` to link this Origin to
  # @option opts [Fixnum] :port The port number of the `Mdm::Service` to link this Origin to
  # @option opts [String] :service_name The service name to use for the `Mdm::Service`
  # @option opts [String] :protocol The protocol type of the `Mdm::Service` to link this Origin to
  # @option opts [String] :module_fullname The fullname of the Metasploit Module to link this Origin to
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::Service] The created {Metasploit::Credential::Origin::Service} object
  def create_credential_origin_service(opts={})
    return nil unless active_db?
    module_fullname  = opts.fetch(:module_fullname)
    service_object = create_credential_service(opts)
    return nil if service_object.nil?

    retry_transaction do
      Metasploit::Credential::Origin::Service.where(service_id: service_object.id, module_full_name: module_fullname).first_or_create!
    end
  end

  # This method is responsible for creating {Metasploit::Credential::Origin::Session} objects.
  #
  # @option opts [Fixnum] :session_id The ID of the `Mdm::Session` to link this Origin to
  # @option opts [String] :post_reference_name The reference name of the Metasploit Post module to link the origin to
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Metasploit::Credential::Origin::Session] The created {Metasploit::Credential::Origin::Session} object
  def create_credential_origin_session(opts={})
    return nil unless active_db?
    session_id           = opts.fetch(:session_id)
    post_reference_name  = opts.fetch(:post_reference_name)

    retry_transaction do
      Metasploit::Credential::Origin::Session.where(session_id: session_id, post_reference_name: post_reference_name).first_or_create!
    end
  end

  # This method is responsible for the creation of {Metasploit::Credential::Private} objects.
  # It will create the correct subclass based on the type.
  #
  # @option opts [String] :jtr_format The format for John the ripper to use to try and crack this
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
    return nil unless active_db?
    private_data = opts.fetch(:private_data)
    private_type = opts.fetch(:private_type)

    private_object = nil

    retry_transaction do
      if private_data.blank?
        private_object = Metasploit::Credential::BlankPassword.where(data:'').first_or_create
      else
        case private_type
        when :password
          private_object = Metasploit::Credential::Password.where(data: private_data).first_or_create
        when :ssh_key
          private_object = Metasploit::Credential::SSHKey.where(data: private_data).first_or_create
        when :ntlm_hash
          private_object = Metasploit::Credential::NTLMHash.where(data: private_data).first_or_create
          private_object.jtr_format = 'nt,lm'
        when :postgres_md5
          private_object = Metasploit::Credential::PostgresMD5.where(data: private_data).first_or_create
          private_object.jtr_format = 'raw-md5,postgres'
        when :nonreplayable_hash
          private_object = Metasploit::Credential::NonreplayableHash.where(data: private_data).first_or_create
          if opts[:jtr_format].present?
            private_object.jtr_format = opts[:jtr_format]
          end
        else
          raise ArgumentError, "Invalid Private type: #{private_type}"
        end
      end
      private_object.save!
    end
    private_object
  end

  # This method is responsible for the creation of {Metasploit::Credential::Public} objects.
  #
  # @option opts [String] :username The username to use for the {Metasploit::Credential::Public}
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no active database connection
  # @return [Metasploit::Credential::Public]
  def create_credential_public(opts={})
    return nil unless active_db?
    username = opts.fetch(:username)

    retry_transaction do
      if username.blank?
        Metasploit::Credential::BlankUsername.where(username:'').first_or_create!
      else
        Metasploit::Credential::Username.where(username: username).first_or_create!
      end
    end
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
    return nil unless active_db?
    realm_key   = opts.fetch(:realm_key)
    realm_value = opts.fetch(:realm_value)

    retry_transaction do
      Metasploit::Credential::Realm.where(key: realm_key, value: realm_value).first_or_create!
    end
  end



  # This method is responsible for creating a barebones `Mdm::Service` object
  # for use by Credential object creation.
  #
  # @option opts [String] :address The address of the `Mdm::Host`
  # @option opts [Fixnum] :port The port number of the `Mdm::Service`
  # @option opts [String] :service_name The service name to use for the `Mdm::Service`
  # @option opts [String] :protocol The protocol type of the `Mdm::Service``
  # @option opts [Fixnum] :workspace_id The ID of the `Mdm::Workspace` to use for the `Mdm::Host`
  # @raise [KeyError] if a required option is missing
  # @return [NilClass] if there is no connected database
  # @return [Mdm::Service]
  def create_credential_service(opts={})
    return nil unless active_db?
    address          = opts.fetch(:address)
    return nil unless Rex::Socket.is_ipv4?(address) || Rex::Socket.is_ipv6?(address)
    port             = opts.fetch(:port)
    service_name     = opts.fetch(:service_name)
    protocol         = opts.fetch(:protocol)
    workspace_id     = opts.fetch(:workspace_id)

    host_object    = Mdm::Host.where(address: address, workspace_id: workspace_id).first_or_create
    service_object = Mdm::Service.where(host_id: host_object.id, port: port, proto: protocol).first_or_initialize

    service_object.name  = service_name
    service_object.state = "open"
    service_object.save!

    service_object
  end

  # This method checks to see if a {Metasploit::Credential::Login} exists for a given
  # set of details. If it does exists, we then appropriately set the status to one of our
  # failure statuses.
  #
  # @option opts [String] :address The address of the host we attempted
  # @option opts [Fixnum] :port the port of the service we attempted
  # @option opts [String] :protocol the transport protocol of the service we attempted
  # @option opts [String] :public A string representation of the public we tried
  # @option opts [String] :private A string representation of the private we tried
  # @option opts [Symbol] :status The status symbol from the {Metasploit::Framework::LoginScanner::Result}
  # @raise [KeyError] if any of the above options are missing
  # @return [void] Do not worry about the return value from this method
  def invalidate_login(opts = {})
    return nil unless active_db?
    address     = opts.fetch(:address)
    return nil unless Rex::Socket.is_ipv4?(address) || Rex::Socket.is_ipv6?(address)
    port        = opts.fetch(:port)
    protocol    = opts.fetch(:protocol)
    public      = opts.fetch(:username, nil)
    private     = opts.fetch(:private_data, nil)
    realm_key   = opts.fetch(:realm_key, nil)
    realm_value = opts.fetch(:realm_value, nil)
    status      = opts.fetch(:status)


    pub_obj = Metasploit::Credential::Public.where(username: public).first.try(:id)
    priv_obj = Metasploit::Credential::Private.where(data: private).first.try(:id)
    realm_obj = Metasploit::Credential::Realm.where(key: realm_key, value: realm_value).first.try(:id)

    core = Metasploit::Credential::Core.where(public_id: pub_obj, private_id: priv_obj, realm_id: realm_obj).first

    # Do nothing else if we have no matching core. Otherwise look for a Login.
    if core.present?
      login = core.logins.joins(service: :host).where(services: { port: port, proto: protocol } ).where( hosts: {address: address}).readonly(false).first

      if login.present?
        login.status = status
        login.last_attempted_at = DateTime.now
        login.save!
      end

    end

  end


  private

  # This method wraps a block in a retry if we get a RecordNotUnique validation error.
  # This helps guard against race conditions.
  def retry_transaction(&block)
    tries = 3
    begin
      yield
    rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique
      tries -= 1
      if tries > 0
        retry
      else
        raise
      end
    end
  end
end
