module Nexpose

  # Object that represents administrative credentials to be used
  # during a scan. When retrieved from an existing site configuration
  # the credentials will be returned as a security blob and can only
  # be passed back as is during a Site Save operation. This object
  # can only be used to create a new set of credentials.
  #
  class SiteCredentials < Credential

    # Unique identifier of the credential on the Nexpose console.
    attr_accessor :id
    # The service for these credentials.
    attr_accessor :service
    # The host for these credentials.
    attr_accessor :host_restriction
    # The port on which to use these credentials.
    attr_accessor :port_restriction
    # The password
    attr_accessor :password
    # The name
    attr_accessor :name
    # is this credential enable on site or not.
    attr_accessor :enabled
    # the description of credential
    attr_accessor :description
    # domain of the service
    attr_accessor :domain
    # database of the service
    attr_accessor :database
    # The type of privilege escalation to use (sudo/su)
    # Permission elevation type. See Nexpose::Credential::ElevationType.
    attr_accessor :permission_elevation_type
    # The userid to use when escalating privileges (optional)
    attr_accessor :permission_elevation_user
    # The password to use when escalating privileges (optional)
    attr_accessor :permission_elevation_password
    # The authentication type to use with SNMP v3 credentials
    attr_accessor :authentication_type
    # The privacy/encryption type to use with SNMP v3 credentials
    attr_accessor :privacy_type
    # The privacy/encryption pass phrase to use with SNMP v3 credentials
    attr_accessor :privacy_password
    # the user name to be used in service
    attr_accessor :user_name
    # the notes password
    attr_accessor :notes_id_password
    # use windows auth
    attr_accessor :use_windows_auth
    # sid for oracle
    attr_accessor :sid
    # for ssh public key require pem format private key
    attr_accessor :pem_format_private_key
    # for snmp v1/v2
    attr_accessor :community_name
    # scope of credential
    attr_accessor :scope

    # Test this credential against a target where the credentials should apply.
    # Only works for a newly created credential. Loading an existing credential
    # will likely fail due to the API not sending password.
    #
    # @param [Connection] nsc An active connection to the security console.
    # @param [String] target Target host to check credentials against.
    # @param [Fixnum] engine_id ID of the engine to use for testing credentials.
    #    Will default to the local engine if none is provided.
    # @param [Fixnum] siteid
    # @return [Boolean] If the credential is able to connect to the target.
    #
    def test(nsc, target, engine_id = nil, siteid = -1)
      unless engine_id
        engine_id = nsc.engines.detect { |e| e.name == 'Local scan engine' }.id
      end
      @port      = Credential::DEFAULT_PORTS[@service] if @port.nil?
      parameters = _to_param(target, engine_id, @port, siteid)
      parameters = JSON.generate(parameters)
      resp       = JSON.parse(Nexpose::AJAX.post(nsc, '/data/credential/test', parameters, Nexpose::AJAX::CONTENT_TYPE::JSON))
      resp['success'] == 'true'
    end

    def _to_param(target, engine_id, port, siteid)
      {
        dev: target,
        port: port,
        siteID: siteid,
        engineID: engine_id,
        service: @service,
        domain: @domain,
        database: @database,
        userName: @user_name,
        password: @password,
        privilegeElevationUserName: @permission_elevation_user,
        privilegeElevationPassword: @permission_elevation_password,
        privilegeElevationType: @permission_elevation_type,
        pemkey: @pem_format_private_key,
        snmpv3AuthType: @authentication_type,
        snmpv3PrivType: @privacy_type,
        snmpv3PrivPassword: @privacy_password
      }
    end

    # Create a credential object using name, id, description, host and port
    def self.for_service(name, id = -1, desc = nil, host = nil, port = nil, service = Credential::Service::CIFS)
      cred                           = new
      cred.name                      = name
      cred.id                        = id.to_i
      cred.enabled                   = true
      cred.description               = desc
      cred.host_restriction          = host
      cred.port_restriction          = port
      cred.service                   = service
      cred.scope                     = Credential::Scope::SITE_SPECIFIC
      cred.permission_elevation_type = Credential::ElevationType::NONE
      cred
    end

    # Load an credential from the provided console.
    #
    # @param [Connection] nsc Active connection to a Nexpose console.
    # @param [String] id Unique identifier of an site.
    # @param [String] id Unique identifier of an credential.
    # @return [SiteCredential] The requested credential of site, if found.
    #
    def self.load(nsc, site_id, credential_id)
      uri  = "/api/2.1/sites/#{site_id}/credentials/#{credential_id}"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true)
      new.object_from_hash(nsc, hash)
    end

    # Copy an existing configuration from a Nexpose instance.
    # Returned object will reset the credential ID and append "Copy" to the existing
    # name.
    # Reminder: The password field will not be populated due to the API not sending password.
    #
    # @param [Connection] connection Connection to the security console.
    # @param [String] id Unique identifier of an site.
    # @param [String] id Unique identifier of an credential.
    # @return [SiteCredentials] Site credential loaded from a Nexpose console.
    #
    def self.copy(connection, site_id, credential_id)
      site_credential      = self.load(connection, site_id, credential_id)
      site_credential.id   = -1
      site_credential.name = "#{site_credential.name} Copy"
      site_credential
    end

    # Copy an existing configuration from a site credential.
    # Returned object will reset the credential ID and append "Copy" to the existing
    # name.
    # Reminder: The password field will not be populated due to the API not sending password.
    #
    # @return [SiteCredentials] modified.
    #
    def copy
      site_credential      = self.clone
      site_credential.id   = -1
      site_credential.name = "#{site_credential.name} Copy"
      site_credential
    end

    def to_json
      JSON.generate(to_h)
    end

    def to_h
      { id: id,
        service: service,
        host_restriction: host_restriction,
        port_restriction: port_restriction,
        password: password,
        name: name,
        enabled: enabled,
        description: description,
        domain: domain,
        database: database,
        permission_elevation_type: permission_elevation_type,
        permission_elevation_user: permission_elevation_user,
        permission_elevation_password: permission_elevation_password,
        authentication_type: authentication_type,
        privacy_type: privacy_type,
        privacy_password: privacy_password,
        user_name: user_name,
        notes_id_password: notes_id_password,
        use_windows_auth: use_windows_auth,
        sid: sid,
        pem_format_private_key: pem_format_private_key,
        community_name: community_name,
        scope: scope }
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      id.eql?(other.id) &&
      service.eql?(other.service) &&
      host_restriction.eql?(other.host_restriction) &&
      port_restriction.eql?(other.port_restriction) &&
      password.eql?(other.password) &&
      name.eql?(other.name) &&
      enabled.eql?(other.enabled) &&
      description.eql?(other.description) &&
      domain.eql?(other.domain) &&
      database.eql?(other.database) &&
      permission_elevation_type.eql?(other.permission_elevation_type) &&
      permission_elevation_user.eql?(other.permission_elevation_user) &&
      permission_elevation_password.eql?(other.permission_elevation_password) &&
      authentication_type.eql?(other.authentication_type) &&
      privacy_type.eql?(other.privacy_type) &&
      privacy_password.eql?(other.privacy_password) &&
      user_name.eql?(other.user_name) &&
      notes_id_password.eql?(other.notes_id_password) &&
      use_windows_auth.eql?(other.use_windows_auth) &&
      sid.eql?(other.sid) &&
      pem_format_private_key.eql?(other.pem_format_private_key) &&
      community_name.eql?(other.community_name) &&
      scope.eql?(other.scope)
    end

  end
end
