module Nexpose

  class Connection

    def list_shared_credentials
      creds = DataTable._get_json_table(self,
                                        '/data/credential/shared/listing',
                                        { 'sort' => -1,
                                          'table-id' => 'credential-listing' })
      creds.map { |c| SharedCredentialSummary.from_json(c) }
    end

    alias list_shared_creds list_shared_credentials
    alias shared_credentials list_shared_credentials
    alias shared_creds list_shared_credentials

    def delete_shared_credential(id)
      AJAX.post(self, "/data/credential/shared/delete?credid=#{id}")
    end

    alias delete_shared_cred delete_shared_credential
  end

  class SharedCredentialSummary < Credential

    # Unique ID assigned to this credential by Nexpose.
    attr_accessor :id
    # Name to identify this credential.
    attr_accessor :name
    # The credential service/type. See Nexpose::Credential::Service.
    attr_accessor :service
    alias type service
    alias type= service=
    # Domain or realm.
    attr_accessor :domain
    # User name.
    attr_accessor :username
    alias user_name username
    alias user_name= username=
    # User name to use when elevating permissions (e.g., sudo).
    attr_accessor :privilege_username
    alias permission_elevation_user privilege_username
    alias permission_elevation_user= privilege_username=
    # Boolean to indicate whether this credential applies to all sites.
    attr_accessor :all_sites
    # When this credential was last modified.
    attr_accessor :last_modified

    def self.from_json(json)
      cred = new
      cred.id                 = json['credentialID']['ID']
      cred.name               = json['name']
      cred.type               = json['service']
      cred.domain             = json['domain']
      cred.username           = json['username']
      cred.privilege_username = json['privilegeElevationUsername']
      cred.all_sites          = json['scope'] == 'ALL_SITES_ENABLED_DEFAULT'
      cred.last_modified      = Time.at(json['lastModified']['time'] / 1000)
      cred
    end

    # Delete this credential from the security console.
    #
    # @param [Connection] nsc An active connection to the security console.
    #
    def delete(nsc)
      nsc.delete_shared_credential(@id)
    end
  end

  class SharedCredential < SharedCredentialSummary

    # Optional description of this credential.
    attr_accessor :description

    # Database or SID.
    attr_accessor :database
    # Windows/Samba LM/NTLM Hash.
    attr_accessor :ntlm_hash
    # Password or SNMP community name.
    attr_accessor :password
    # PEM-format private key.
    attr_accessor :pem_key
    # Password to use when elevating permissions (e.g., sudo).
    attr_accessor :privilege_password
    alias permission_elevation_password privilege_password
    alias permission_elevation_password= privilege_password=
    # Permission elevation type. See Nexpose::Credential::ElevationType.
    attr_accessor :privilege_type
    alias permission_elevation_type privilege_type
    alias permission_elevation_type= privilege_type=
    # Privacty password of SNMP v3 credential
    attr_accessor :privacy_password
    # Authentication type of SNMP v3 credential
    attr_accessor :auth_type
    # Privacy type of SNMP v3 credential
    attr_accessor :privacy_type
    # IP address or host name to restrict this credential to.
    attr_accessor :host
    # Single port to restrict this credential to.
    attr_accessor :port

    # Array of site IDs that this credential is restricted to.
    attr_accessor :sites
    # Array of sites where this credential has been temporarily disabled.
    attr_accessor :disabled

    def initialize(name, id = -1)
      @name     = name
      @id       = id.to_i
      @sites    = []
      @disabled = []
    end

    def self.load(nsc, id)
      response = AJAX.get(nsc, "/data/credential/shared/get?credid=#{id}")
      parse(response)
    end

    # Save this credential to the security console.
    #
    # @param [Connection] nsc An active connection to a Nexpose console.
    # @return [Boolean] Whether the save succeeded.
    #
    def save(nsc)
      response = AJAX.post(nsc, '/data/credential/shared/save', to_xml)
      !!(response =~ /success="1"/)
    end

    def as_xml
      xml = REXML::Element.new('Credential')
      xml.add_attribute('id', @id)
      xml.add_element('Name').add_text(@name)
      xml.add_element('Description').add_text(@description)

      services = xml.add_element('Services')
      services.add_element('Service').add_attribute('type', @service)

      (account = xml.add_element('Account')).add_attribute('type', 'nexpose')
      account.add_element('Field', { 'name' => 'database' }).add_text(@database)
      account.add_element('Field', { 'name' => 'domain' }).add_text(@domain)
      account.add_element('Field', { 'name' => 'username' }).add_text(@username)
      account.add_element('Field', { 'name' => 'ntlmhash' }).add_text(@ntlm_hash) if @ntlm_hash
      account.add_element('Field', { 'name' => 'password' }).add_text(@password) if @password
      account.add_element('Field', { 'name' => 'pemkey' }).add_text(@pem_key) if @pem_key
      account.add_element('Field', { 'name' => 'privilegeelevationusername' }).add_text(@privilege_username)
      account.add_element('Field', { 'name' => 'privilegeelevationpassword' }).add_text(@privilege_password) if @privilege_password
      account.add_element('Field', { 'name' => 'privilegeelevationtype' }).add_text(@privilege_type) if @privilege_type
      account.add_element('Field', { 'name' => 'snmpv3authtype' }).add_text(@auth_type) if @auth_type
      account.add_element('Field', { 'name' => 'snmpv3privtype' }).add_text(@privacy_type) if @privacy_type
      account.add_element('Field', { 'name' => 'snmpv3privpassword' }).add_text(@privacy_password) if @privacy_password

      restrictions = xml.add_element('Restrictions')
      restrictions.add_element('Restriction', { 'type' => 'host' }).add_text(@host) if @host
      restrictions.add_element('Restriction', { 'type' => 'port' }).add_text(@port) if @port

      sites = xml.add_element('Sites')
      sites.add_attribute('all', @all_sites ? 1 : 0)
      @sites.each do |s|
        site = sites.add_element('Site')
        site.add_attribute('id', s)
        site.add_attribute('enabled', 0) if @disabled.member? s
      end
      if @sites.empty?
        @disabled.each do |s|
          site = sites.add_element('Site')
          site.add_attribute('id', s)
          site.add_attribute('enabled', 0)
        end
      end

      xml
    end

    # Test this credential against a target where the credentials should apply.
    # Only works for a newly created credential. Loading an existing credential
    # will likely fail due to the API not sending password.
    #
    # @param [Connection] nsc An active connection to the security console.
    # @param [String] target Target host to check credentials against.
    # @param [Fixnum] engine_id ID of the engine to use for testing credentials.
    #   Will default to the local engine if none is provided.
    #
    def test(nsc, target, engine_id = nil, siteid = -1)
      unless engine_id
        engine_id = nsc.engines.detect { |e| e.name == 'Local scan engine' }.id
      end
      @port      = Credential::DEFAULT_PORTS[@service] if @port.nil?
      parameters = _to_param(target, engine_id, @port, siteid)
      xml        = AJAX.form_post(nsc, '/data/credential/shared/test', parameters)
      result     = REXML::XPath.first(REXML::Document.new(xml), 'TestAdminCredentialsResult')
      result.attributes['success'].to_i == 1
    end

    def _to_param(target, engine_id, port, siteid)
      { engineid: engine_id,
        sc_creds_dev: target,
        sc_creds_svc: @service,
        sc_creds_database: @database,
        sc_creds_domain: @domain,
        sc_creds_uname: @username,
        sc_creds_password: @password,
        sc_creds_pemkey: @pem_key,
        sc_creds_port: port,
        sc_creds_privilegeelevationusername: @privilege_username,
        sc_creds_privilegeelevationpassword: @privilege_password,
        sc_creds_privilegeelevationtype: @privilege_type,
        sc_creds_snmpv3authtype: @auth_type,
        sc_creds_snmpv3privtype: @privacy_type,
        sc_creds_snmpv3privpassword: @privacy_password,
        siteid: siteid }
    end

    def to_xml
      as_xml.to_s
    end

    def self.parse(xml)
      rexml = REXML::Document.new(xml)
      rexml.elements.each('Credential') do |c|
        cred = new(c.elements['Name'].text, c.attributes['id'].to_i)

        desc = c.elements['Description']
        cred.description = desc.text if desc

        c.elements.each('Account/Field') do |field|
          case field.attributes['name']
          when 'database'
            cred.database = field.text
          when 'domain'
            cred.domain = field.text
          when 'username'
            cred.username = field.text
          when 'password'
            cred.password = field.text
          when 'ntlmhash'
            cred.ntlm_hash = field.text
          when 'pemkey'
            cred.pem_key = field.text
          when 'privilegeelevationusername'
            cred.privilege_username = field.text
          when 'privilegeelevationpassword'
            cred.privilege_password = field.text
          when 'privilegeelevationtype'
            cred.privilege_type = field.text
          when 'snmpv3authtype'
            cred.auth_type = field.text
          when 'snmpv3privtype'
            cred.privacy_type = field.text
          when 'snmpv3privpassword'
            cred.privacy_password = field.text
          end
        end

        service = REXML::XPath.first(c, 'Services/Service')
        cred.type = service.attributes['type']

        c.elements.each('Restrictions/Restriction') do |r|
          cred.host = r.text if r.attributes['type'] == 'host'
          cred.port = r.text.to_i if r.attributes['type'] == 'port'
        end

        sites = REXML::XPath.first(c, 'Sites')
        cred.all_sites = sites.attributes['all'] == '1'

        sites.elements.each('Site') do |site|
          site_id = site.attributes['id'].to_i
          cred.sites << site_id unless cred.all_sites
          cred.disabled << site_id if site.attributes['enabled'] == '0'
        end

        return cred
      end
      nil
    end
  end
end
