module Nexpose

  class Connection
    include XMLUtils

    # Retrieve a list of all users configured on this console.
    #
    # @return [Array[UserSummary]] Array of users.
    #
    def list_users
      r = execute(make_xml('UserListingRequest'))
      arr = []
      if r.success
        r.res.elements.each('UserListingResponse/UserSummary') do |summary|
          arr << UserSummary.parse(summary)
        end
      end
      arr
    end

    alias users list_users

    # Retrieve the User ID based upon the user's login name.
    #
    # @param [String] user_name User name to search for.
    #
    def get_user_id(user_name)
      users.find { |user| user.name.eql? user_name }
    end

    # Delete a user from the Nexpose console.
    #
    # @param [Fixnum] user_id Unique ID for the user to delete.
    # @return [Boolean] Whether or not the user deletion succeeded.
    #
    def delete_user(user_id)
      response = execute(make_xml('UserDeleteRequest', { 'id' => user_id }))
      response.success
    end
  end

  # Summary only returned by API when issuing a listing request.
  #
  class UserSummary

    attr_reader :id, :auth_source, :auth_module, :name, :full_name, :email
    attr_reader :is_admin, :is_disabled, :is_locked, :site_count, :group_count

    def initialize(id, auth_source, auth_module, name, full_name, email, is_admin, is_disabled, is_locked, site_count, group_count)
      @id          = id
      @auth_source = auth_source
      @auth_module = auth_module
      @name        = name
      @full_name   = full_name
      @email       = email
      @is_admin    = is_admin
      @is_disabled = is_disabled
      @is_locked   = is_locked
      @site_count  = site_count
      @group_count = group_count
    end

    # Provide a list of user accounts and information about those accounts.
    def self.parse(summary)
      new(summary.attributes['id'].to_i,
          summary.attributes['authSource'],
          summary.attributes['authModule'],
          summary.attributes['userName'],
          summary.attributes['fullName'],
          summary.attributes['email'],
          summary.attributes['administrator'].to_s.chomp.eql?('1'),
          summary.attributes['disabled'].to_s.chomp.eql?('1'),
          summary.attributes['locked'].to_s.chomp.eql?('1'),
          summary.attributes['siteCount'].to_i,
          summary.attributes['groupCount'].to_i)
    end
  end

  class User
    include Sanitize

    # user id, set to -1 to create a new user
    attr_reader :id
    # valid roles: global-admin|security-manager|site-admin|system-admin|user|custom|controls-insight-only
    attr_accessor :role_name
    # Required fields
    attr_reader :name
    attr_accessor :full_name
    # Will default to XML (1) for global-admin, Data Source (2) otherwise,
    # but caller can override (e.g., using LDAP authenticator).
    attr_accessor :authsrcid
    # Optional fields
    attr_accessor :email, :password, :sites, :groups, :token
    # 1 to enable this user, 0 to disable
    attr_accessor :enabled
    # Boolean values
    attr_accessor :all_sites, :all_groups

    def initialize(name, full_name, password, role_name = 'user', id = -1, enabled = 1, email = nil, all_sites = false, all_groups = false, token = nil)
      @name       = name
      @password   = password
      @token      = token
      @role_name  = role_name
      @authsrcid  = 'global-admin'.eql?(@role_name) ? '1' : '2'
      @id         = id
      @enabled    = enabled
      @full_name  = full_name
      @email      = email
      @all_sites  = all_sites || role_name == 'global-admin'
      @all_groups = all_groups || role_name == 'global-admin'
      @sites      = []
      @groups     = []
    end

    def to_xml
      xml = '<UserConfig'
      xml << %( id="#{@id}" )
      xml << %( authsrcid="#{@authsrcid}" )
      xml << %( name="#{replace_entities(@name)}" )
      xml << %( fullname="#{replace_entities(@full_name)}" )
      xml << %( role-name="#{replace_entities(@role_name)}" )
      xml << %( password="#{replace_entities(@password)}" ) if @password
      xml << %( token="#{replace_entities(@token)}" ) if @token
      xml << %( email="#{replace_entities(@email)}" ) if @email
      xml << %( enabled="#{@enabled}" )
      # These two fields are keying off role_name to work around a defect.
      xml << %( allGroups="#{@all_groups || @role_name == 'global-admin'}" )
      xml << %( allSites="#{@all_sites || @role_name == 'global-admin'}" )
      xml << '>'
      @sites.each do |site|
        xml << %( <site id="#{site}" /> )
      end
      @groups.each do |group|
        xml << %( <group id="#{group}" /> )
      end
      xml << '</UserConfig>'
    end

    # Save a user configuration. Returns the (new) user ID if successful.
    def save(connection)
      xml = '<UserSaveRequest session-id="' + connection.session_id + '">'
      xml << to_xml
      xml << '</UserSaveRequest>'
      r = connection.execute(xml, '1.1')
      if r.success
        r.res.elements.each('UserSaveResponse') do |attr|
          @id = attr.attributes['id'].to_i
        end
        @id
      else
        -1
      end
    end

    # Issue a UserConfigRequest to load an existing UserConfig from Nexpose.
    def self.load(connection, user_id)
      xml = '<UserConfigRequest session-id="' + connection.session_id + '"'
      xml << %( id="#{user_id}" )
      xml << ' />'
      r = connection.execute(xml, '1.1')
      if r.success
        r.res.elements.each('UserConfigResponse/UserConfig') do |config|
          id         = config.attributes['id']
          role_name  = config.attributes['role-name']
          # authsrcid  = config.attributes['authsrcid']
          name       = config.attributes['name']
          fullname   = config.attributes['fullname']

          email      = config.attributes['email']
          password   = config.attributes['password']
          token      = config.attributes['token']
          enabled    = config.attributes['enabled'].to_i
          all_sites  = config.attributes['allSites'] == 'true' ? true : false
          all_groups = config.attributes['allGroups'] == 'true' ? true : false
          # Not trying to load sites and groups.
          # Looks like API currently doesn't return that info to load.
          return User.new(name, fullname, password, role_name, id, enabled, email, all_sites, all_groups, token)
        end
      end
    end

    # Delete the user account associated with this object.
    def delete(connection)
      connection.delete_user(@id)
    end
  end

  class UserAuthenticator

    attr_reader :id, :auth_source, :auth_module, :external

    def initialize(id, auth_module, auth_source, external = false)
      @id = id
      @auth_source = auth_source
      @auth_module = auth_module
      @external = external
    end

    # Provide a list of user authentication sources.
    # * *Returns* : An array of known user authenticator sources.
    def self.list(connection)
      r = connection.execute('<UserAuthenticatorListingRequest session-id="' + connection.session_id + '" />', '1.1')
      modules = []
      if r.success
        r.res.elements.each('UserAuthenticatorListingResponse/AuthenticatorSummary') do |summary|
          modules << UserAuthenticator.new(summary.attributes['id'], summary.attributes['authModule'], summary.attributes['authSource'], ('1'.eql? summary.attributes['external']))
        end
      end
      modules
    end
  end
end
