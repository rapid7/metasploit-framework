module Nexpose

  class Connection
    include XMLUtils

    # Retrieve a list of all silos the user is authorized to view or manage.
    #
    # @return [Array[SiloSummary]] Array of SiloSummary objects.
    #
    def list_silos
      r = execute(make_xml('SiloListingRequest'), '1.2')
      arr = []
      if r.success
        r.res.elements.each('SiloListingResponse/SiloSummaries/SiloSummary') do |silo|
          arr << SiloSummary.parse(silo)
        end
      end
      arr
    end

    alias silos list_silos

    # Delete the specified silo
    #
    # @return Whether or not the delete request succeeded.
    #
    def delete_silo(silo_id)
      r = execute(make_xml('SiloDeleteRequest', { 'silo-id' => silo_id }), '1.2')
      r.success
    end
  end

  class Silo
    # Required fields
    attr_accessor :id
    attr_accessor :profile_id
    attr_accessor :name
    attr_accessor :max_assets
    attr_accessor :max_users
    attr_accessor :max_hosted_assets

    # Optional fields
    attr_accessor :description
    attr_accessor :merchant
    attr_accessor :organization

    def initialize(&block)
      instance_eval(&block) if block_given?
    end

    # Copy an existing configuration from a Nexpose instance.
    # Returned object will reset the silo ID and name
    #
    # @param [Connection] connection Connection to the security console.
    # @param [String] id Silo ID of an existing silo.
    # @return [Silo] Silo configuration loaded from a Nexpose console.
    #
    def self.copy(connection, id)
      silo      = load(connection, id)
      silo.id   = nil
      silo.name = nil
      silo
    end

    # Load an existing configuration from a Nexpose instance.
    #
    # @param [Connection] connection Connection to console where site exists.
    # @param [String] id Silo ID of an existing silo.
    # @return [Silo] Silo configuration loaded from a Nexpose console.
    #
    def self.load(connection, id)
      r = connection.execute(connection.make_xml('SiloConfigRequest', { 'silo-id' => id }), '1.2')

      if r.success
        r.res.elements.each('SiloConfigResponse/SiloConfig') do |config|
          return Silo.parse(config)
        end
      end
      nil
    end

    def save(connection)
      update(connection)
    rescue APIError => error
      raise error unless error.message =~ /A silo .* does not exist./
      create(connection)
    end

    # Updates this silo on a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this silo will be saved.
    # @return [String] Silo ID assigned to this configuration, if successful.
    #
    def update(connection)
      xml = connection.make_xml('SiloUpdateRequest')
      xml.add_element(as_xml)
      r = connection.execute(xml, '1.2')
      @id = r.attributes['id'] if r.success
    end

    # Saves a new silo to a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this silo will be saved.
    # @return [String] Silo ID assigned to this configuration, if successful.
    #
    def create(connection)
      xml = connection.make_xml('SiloCreateRequest')
      xml.add_element(as_xml)
      r = connection.execute(xml, '1.2')
      @id = r.attributes['id'] if r.success
    end

    def delete(connection)
      connection.delete_silo(@id)
    end

    def as_xml
      xml = REXML::Element.new('SiloConfig')
      xml.add_attributes({ 'description' => @description, 'name' => @name, 'id' => @id, 'silo-profile-id' => @profile_id,
                           'max-assets' => @max_assets, 'max-users' => @max_users, 'max-hosted-assets' => @max_hosted_assets })
      xml.add(@merchant.as_xml) if @merchant
      xml.add(@organization.as_xml) if @organization
      xml
    end

    def to_xml
      as_xml.to_s
    end

    def self.parse(xml)
      new do |silo|
        silo.id                = xml.attributes['id']
        silo.profile_id        = xml.attributes['silo-profile-id']
        silo.name              = xml.attributes['name']
        silo.max_assets        = xml.attributes['max-assets'].to_i
        silo.max_users         = xml.attributes['max-users'].to_i
        silo.max_hosted_assets = xml.attributes['max-hosted-assets'].to_i
        silo.description       = xml.attributes['description']

        xml.elements.each('Merchant') do |merchant|
          silo.merchant = Merchant.parse(merchant)
        end

        xml.elements.each('Organization') do |organization|
          silo.organization = Organization.parse(organization)
        end
      end
    end

    class Address
      attr_accessor :line1
      attr_accessor :line2
      attr_accessor :city
      attr_accessor :state
      attr_accessor :zip
      attr_accessor :country

      def initialize(&block)
        instance_eval(&block) if block_given?
      end

      def self.parse(xml)
        new do |address|
          address.line1   = xml.attributes['line1']
          address.line2   = xml.attributes['line2']
          address.city    = xml.attributes['city']
          address.state   = xml.attributes['state']
          address.zip     = xml.attributes['zip']
          address.country = xml.attributes['country']
        end
      end

      def as_xml
        xml = REXML::Element.new('Address')
        xml.add_attributes({ 'city' => @city, 'country' => @country, 'line1' => @line1, 'line2' => @line2, 'state' => @state, 'zip' => @zip })
        xml
      end
    end

    class Organization
      attr_accessor :company
      attr_accessor :first_name
      attr_accessor :last_name
      attr_accessor :phone
      attr_accessor :address
      attr_accessor :email
      attr_accessor :title
      attr_accessor :url

      def initialize(&block)
        instance_eval(&block) if block_given?
      end

      def as_xml
        xml = REXML::Element.new('Organization')
        xml.add_attributes({ 'company' => @company, 'email-address' => @email, 'first-name' => @first_name,
                             'last-name' => @last_name, 'phone-number' => @phone, 'title' => @title, 'url' => @url })
        xml.add(@address.as_xml)
        xml
      end

      def self.parse(xml)
        new do |organization|
          organization.company    = xml.attributes['company']
          organization.first_name = xml.attributes['first-name']
          organization.last_name  = xml.attributes['last-name']
          organization.phone      = xml.attributes['phone-number']
          xml.elements.each('Address') do |address|
            organization.address = Address.parse(address)
          end
          organization.email = xml.attributes['email']
          organization.title = xml.attributes['title']
          organization.url   = xml.attributes['url']
        end
      end
    end

    class Merchant < Organization
      attr_accessor :acquirer_relationship
      attr_accessor :agent_relationship
      attr_accessor :ecommerce
      attr_accessor :grocery
      attr_accessor :mail_order
      attr_accessor :payment_application
      attr_accessor :payment_version
      attr_accessor :petroleum
      attr_accessor :retail
      attr_accessor :telecommunication
      attr_accessor :travel
      attr_accessor :dbas
      attr_accessor :industries
      attr_accessor :qsa

      def initialize(&block)
        instance_eval(&block) if block_given?
        @dbas       = Array(@dbas)
        @industries = Array(@industries)
        @qsa        = Array(@qsa)
      end

      def self.parse(xml)
        new do |merchant|
          merchant.acquirer_relationship = xml.attributes['acquirer-relationship'].to_s.chomp.eql?('true')
          merchant.agent_relationship    = xml.attributes['agent-relationship'].to_s.chomp.eql?('true')
          merchant.ecommerce             = xml.attributes['ecommerce'].to_s.chomp.eql?('true')
          merchant.grocery               = xml.attributes['grocery'].to_s.chomp.eql?('true')
          merchant.mail_order            = xml.attributes['mail-order'].to_s.chomp.eql?('true')
          merchant.payment_application   = xml.attributes['payment-application']
          merchant.payment_version       = xml.attributes['payment-version']
          merchant.petroleum             = xml.attributes['petroleum'].to_s.chomp.eql?('true')
          merchant.retail                = xml.attributes['retail'].to_s.chomp.eql?('true')
          merchant.telecommunication     = xml.attributes['telecommunication'].to_s.chomp.eql?('true')
          merchant.travel                = xml.attributes['travel'].to_s.chomp.eql?('true')
          merchant.company               = xml.attributes['company']
          merchant.first_name            = xml.attributes['first-name']
          merchant.last_name             = xml.attributes['last-name']
          merchant.phone                 = xml.attributes['phone-number']
          merchant.email                 = xml.attributes['email']
          merchant.title                 = xml.attributes['title']
          merchant.url                   = xml.attributes['url']

          xml.elements.each('Address') do |address|
            merchant.address = Address.parse(address)
          end

          merchant.dbas = []
          xml.elements.each('DBAs/DBA') do |dba|
            merchant.dbas << dba.attributes['name']
          end

          merchant.industries = []
          xml.elements.each('OtherIndustries/Industry') do |industry|
            merchant.industries << industry.attributes['name']
          end

          merchant.qsa = []
          xml.elements.each('QSA') do |organization|
            merchant.qsa << Organization.parse(organization)
          end
        end
      end

      def as_xml
        xml = super
        xml.name = 'Merchant'
        xml.add_attributes({ 'acquirer-relationship' => @acquirer_relationship, 'agent-relationship' => @agent_relationship,
                             'ecommerce' => @ecommerce, 'grocery' => @grocery, 'mail-order' => @mail_order })
        xml.add_attributes({ 'payment-application' => @payment_application, 'payment-version' => @payment_version,
                             'petroleum' => @petroleum, 'retail' => @retail, 'telecommunication' => @telecommunication, 'travel' => @travel })

        unless dbas.empty?
          dbas = REXML::Element.new('DBAs')
          @dbas.each do |dba|
            dbas.add_element('DBA', { 'name' => dba })
          end
        end

        unless @industries.empty?
          industries = REXML::Element.new('OtherIndustries')
          @industries.each do |industry|
            industries.add_element('Industry', { 'name' => industry })
          end
        end

        xml.add(@qsa.as_xml) unless @qsa.empty?

        xml
      end
    end
  end

  # Object that represents the summary of a Nexpose Site.
  #
  class SiloSummary
    # The silo ID.
    attr_reader :id
    # The silo name.
    attr_reader :name
    # A description of the silo.
    attr_reader :description
    # The ID of the silo profile being used for this silo.
    attr_reader :profile_id
    # The asset count for this silo
    attr_reader :assets
    # The asset count limit for this silo.
    attr_reader :max_assets
    # The hosted asset count limit for this silo.
    attr_reader :max_hosted_assets
    # The user count for this silo
    attr_reader :users
    # The user count limit for this silo.
    attr_reader :max_users

    def initialize(&block)
      instance_eval(&block) if block_given?
    end

    def self.parse(xml)
      new do
        @id          = xml.attributes['id']
        @name        = xml.attributes['name']
        @description = xml.attributes['description']
        @profile_id  = xml.attributes['silo-profile-id']
        xml.elements.each('LicenseSummary') do |license|
          @assets            = license.attributes['assets']
          @max_assets        = license.attributes['max-assets']
          @max_hosted_assets = license.attributes['max-hosted-assets']
          @users             = license.attributes['users']
          @max_users         = license.attributes['max-users']
        end
      end
    end
  end

end
