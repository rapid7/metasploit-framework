module Nexpose

  class Connection
    include XMLUtils

    # Retrieve a list of all users the user is authorized to view or manage.
    #
    # @return [Array[MultiTenantUserSummary]] Array of MultiTenantUserSummary objects.
    #
    def list_silo_users
      r = execute(make_xml('MultiTenantUserListingRequest'), '1.2')
      arr = []
      if r.success
        r.res.elements.each('MultiTenantUserListingResponse/MultiTenantUserSummaries/MultiTenantUserSummary') do |user|
          arr << MultiTenantUserSummary.parse(user)
        end
      end
      arr
    end
    alias silo_users list_silo_users

    # Delete the specified silo user
    #
    # @return Whether or not the delete request succeeded.
    #
    def delete_silo_user(user_id)
      r = execute(make_xml('MultiTenantUserDeleteRequest', { 'user-id' => user_id }), '1.2')
      r.success
    end
  end

  class MultiTenantUserSummary
    attr_reader :id
    attr_reader :full_name
    attr_reader :user_name
    attr_reader :email
    attr_reader :superuser
    attr_reader :enabled
    attr_reader :auth_module
    attr_reader :auth_source
    attr_reader :silo_count
    attr_reader :locked

    def initialize(&block)
      instance_eval(&block) if block_given?
    end

    def self.parse(xml)
      new do
        @id          = xml.attributes['id'].to_i
        @full_name   = xml.attributes['full-name']
        @user_name   = xml.attributes['user-name']
        @email       = xml.attributes['email']
        @superuser   = xml.attributes['superuser'].to_s.chomp.eql?('true')
        @enabled     = xml.attributes['enabled'].to_s.chomp.eql?('true')
        @auth_module = xml.attributes['auth-module']
        @auth_source = xml.attributes['auth-source']
        @silo_count  = xml.attributes['silo-count'].to_i
        @locked      = xml.attributes['locked'].to_s.chomp.eql?('true')
      end
    end
  end

  class MultiTenantUser
    attr_accessor :id
    attr_accessor :full_name
    attr_accessor :user_name
    attr_accessor :auth_source_id
    attr_accessor :email
    attr_accessor :password
    attr_accessor :superuser
    attr_accessor :enabled
    attr_accessor :silo_access

    def initialize(&block)
      instance_eval(&block) if block_given?

      @silo_access = Array(@silo_access)
    end

    def save(connection)
      if @id
        update(connection)
      else
        create(connection)
      end
    end

    # Updates this silo user on a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this silo user will be saved.
    # @return [String] User ID assigned to this configuration, if successful.
    #
    def update(connection)
      xml = connection.make_xml('MultiTenantUserUpdateRequest')
      xml.add_element(as_xml)
      r = connection.execute(xml, '1.2')
      @id = r.attributes['user-id'] if r.success
    end

    # Saves this silo user to a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this silo user will be saved.
    # @return [String] User ID assigned to this configuration, if successful.
    #
    def create(connection)
      xml = connection.make_xml('MultiTenantUserCreateRequest')
      xml.add_element(as_xml)
      r = connection.execute(xml, '1.2')
      @id = r.attributes['user-id'] if r.success
    end

    def as_xml
      xml = REXML::Element.new('MultiTenantUserConfig')
      xml.add_attributes({ 'id'        => @id,
                           'full-name' => @full_name,
                           'user-name' => @user_name,
                           'authsrcid' => @auth_source_id,
                           'email'     => @email,
                           'password'  => @password,
                           'superuser' => @superuser,
                           'enabled'   => @enabled })
      siloaccesses = xml.add_element('SiloAccesses')
      @silo_access.each { |silo_access| siloaccesses.add_element(silo_access.as_xml) }
      xml
    end

    def delete(connection)
      connection.delete_silo_user(@id)
    end

    def to_xml
      as_xml.to_s
    end

    def self.parse(xml)
      new do |user|
        user.id             = xml.attributes['id'].to_i
        user.full_name      = xml.attributes['full-name']
        user.user_name      = xml.attributes['user-name']
        user.email          = xml.attributes['email']
        user.superuser      = xml.attributes['superuser'].to_s.chomp.eql?('true')
        user.enabled        = xml.attributes['enabled'].to_s.chomp.eql?('true')
        user.auth_source_id = xml.attributes['authsrcid'].to_i
        user.silo_access    = []
        xml.elements.each('SiloAccesses/SiloAccess') { |access| user.silo_access << SiloAccess.parse(access) }
      end
    end

    def self.load(connection, user_id)
      r = connection.execute(connection.make_xml('MultiTenantUserConfigRequest', { 'user-id' => user_id }), '1.2')

      if r.success
        r.res.elements.each('MultiTenantUserConfigResponse/MultiTenantUserConfig') do |config|
          return MultiTenantUser.parse(config)
        end
      end
      nil
    end
  end

  class SiloAccess
    attr_accessor :all_groups
    attr_accessor :all_sites
    attr_accessor :role_name
    attr_accessor :silo_id
    attr_accessor :default
    attr_accessor :sites
    attr_accessor :groups

    def initialize(&block)
      instance_eval(&block) if block_given?
      @sites = Array(@sites)
      @groups = Array(@groups)
    end

    def as_xml
      xml = REXML::Element.new('SiloAccess')
      xml.add_attributes({ 'all-groups'   => @all_groups,
                           'all-sites'    => @all_sites,
                           'role-name'    => @role_name,
                           'silo-id'      => @silo_id,
                           'default-silo' => @default })

      unless @groups.empty?
        groups = xml.add_element('AllowedGroups')
        @groups.each do |group|
          groups.add_element('AllowedGroup', { 'id' => group })
        end
      end

      unless @sites.empty?
        sites = xml.add_element('AllowedSites')
        @sites.each do |site|
          sites.add_element('AllowedSite', { 'id' => site })
        end
      end

      xml
    end

    def to_xml
      as_xml.to_s
    end

    def self.parse(xml)
      new do |access|
        access.all_groups = xml.attributes['all-groups'].to_s.chomp.eql?('true')
        access.all_sites  = xml.attributes['all-sites'].to_s.chomp.eql?('true')
        access.role_name  = xml.attributes['role-name']
        access.silo_id    = xml.attributes['silo-id']
        access.default    = xml.attributes['default-silo'].to_s.chomp.eql?('true')
        access.sites      = []
        xml.elements.each('AllowedSites/AllowedSite') { |site| access.sites << site.attributes['id'].to_i }
        access.groups = []
        xml.elements.each('AllowedGroups/AllowedGroup') { |group| access.groups << group.attributes['id'].to_i }
      end
    end
  end
end
