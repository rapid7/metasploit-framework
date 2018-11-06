module Nexpose

  class Connection
    include XMLUtils

    # Retrieve a list of all sites the user is authorized to view or manage.
    #
    # @return [Array[SiteSummary]] Array of SiteSummary objects.
    #
    def list_sites
      r = execute(make_xml('SiteListingRequest'))
      arr = []
      if r.success
        r.res.elements.each('SiteListingResponse/SiteSummary') do |site|
          arr << SiteSummary.new(site.attributes['id'].to_i,
                                 site.attributes['name'],
                                 site.attributes['description'],
                                 site.attributes['riskfactor'].to_f,
                                 site.attributes['riskscore'].to_f)
        end
      end
      arr
    end

    alias sites list_sites

    # Delete the specified site and all associated scan data.
    #
    # @return Whether or not the delete request succeeded.
    #
    def delete_site(site_id)
      r = execute(make_xml('SiteDeleteRequest', { 'site-id' => site_id }))
      r.success
    end

    # Retrieve a list of all previous scans of the site.
    #
    # @param [FixNum] site_id Site ID to request scan history for.
    # @return [Array[ScanSummary]] Array of ScanSummary objects representing
    #   each scan run to date on the site provided.
    #
    def site_scan_history(site_id)
      r = execute(make_xml('SiteScanHistoryRequest', { 'site-id' => site_id }))
      scans = []
      if r.success
        r.res.elements.each('SiteScanHistoryResponse/ScanSummary') do |scan_event|
          scans << ScanSummary.parse(scan_event)
        end
      end
      scans
    end

    # Retrieve the scan summary statistics for the latest completed scan
    # on a site.
    #
    # Method will not return data on an active scan.
    #
    # @param [FixNum] site_id Site ID to find latest scan for.
    # @return [ScanSummary] details of the last completed scan for a site.
    #
    def last_scan(site_id)
      site_scan_history(site_id).select(&:end_time).max_by(&:end_time)
    end

    # Retrieve a history of the completed scans for a given site.
    #
    # @param [FixNum] site_id Site ID to find scans for.
    # @return [CompletedScan] details of the completed scans for the site.
    #
    def completed_scans(site_id)
      table = { 'table-id' => 'site-completed-scans' }
      data  = DataTable._get_json_table(self, "/data/scan/site/#{site_id}", table)
      data.map(&CompletedScan.method(:parse_json))
    end
  end

  # Configuration object representing a Nexpose site.
  #
  # For a basic walk-through, see {https://github.com/rapid7/nexpose-client/wiki/Using-Sites}
  class Site < APIObject
    include JsonSerializer
    # The site ID. An ID of -1 is used to designate a site that has not been
    # saved to a Nexpose console.
    attr_accessor :id

    # Unique name of the site. Required.
    attr_accessor :name

    # Description of the site.
    attr_accessor :description

    # Included scan targets. May be IPv4, IPv6, DNS names, IPRanges or assetgroup ids.
    attr_accessor :included_scan_targets

    # Excluded scan targets. May be IPv4, IPv6, DNS names, IPRanges or assetgroup ids.
    attr_accessor :excluded_scan_targets

    # Scan template to use when starting a scan job. Default: full-audit-without-web-spider
    attr_accessor :scan_template_id

    # Friendly name of scan template to use when starting a scan job.
    # Value is populated when a site is saved or loaded from a console.
    attr_accessor :scan_template_name

    # Scan Engine to use. Will use the default engine if nil or -1.
    attr_accessor :engine_id

    # [Array] Schedule starting dates and times for scans, and set their frequency.
    attr_accessor :schedules

    # [Array] Blackout starting dates, times and duration for blackout periods.
    attr_accessor :blackouts

    # The risk factor associated with this site. Default: 1.0
    attr_accessor :risk_factor

    # [Array] Collection of credentials associated with this site. Does not
    # include shared credentials.
    attr_accessor :site_credentials

    # [Array] Collection of shared credentials associated with this site.
    attr_accessor :shared_credentials

    # [Array] Collection of web credentials associated with the site.
    attr_accessor :web_credentials

    # Scan the assets with last scanned engine or not.
    attr_accessor :auto_engine_selection_enabled

    # [Array] Collection of real-time alerts.
    # @see Alert
    # @see SMTPAlert
    # @see SNMPAlert
    # @see SyslogAlert
    attr_accessor :alerts

    # Information about the organization that this site belongs to.
    # Used by some reports.
    attr_accessor :organization

    # [Array] List of user IDs for users who have access to the site.
    attr_accessor :users

    # Configuration version. Default: 3
    attr_accessor :config_version

    # Asset filter criteria if this site is dynamic.
    attr_accessor :search_criteria

    # discovery config of the discovery connection associated with this site if it is dynamic.
    attr_accessor :discovery_config

    # [Array[TagSummary]] Collection of TagSummary
    attr_accessor :tags

    # Site constructor. Both arguments are optional.
    #
    # @param [String] name Unique name of the site.
    # @param [String] scan_template_id ID of the scan template to use.
    def initialize(name = nil, scan_template_id = 'full-audit-without-web-spider')
      @name                  = name
      @scan_template_id      = scan_template_id
      @id                    = -1
      @risk_factor           = 1.0
      @config_version        = 3
      @schedules             = []
      @blackouts             = []
      @included_scan_targets = { addresses: [], asset_groups: [] }
      @excluded_scan_targets = { addresses: [], asset_groups: [] }
      @site_credentials      = []
      @shared_credentials    = []
      @web_credentials       = []
      @alerts                = []
      @users                 = []
      @tags                  = []
    end

    # Returns the array of included scan target addresses.
    # @return [Array[IPRange|HostName]] Array of included addresses.
    def included_addresses
      @included_scan_targets[:addresses]
    end

    # Sets the array of included scan target addresses.
    # @param [Array[IPRange|HostName]] new_addresses The new array of scan target addresses.
    # @return [Array[IPRange|HostName]] Array of updated scan target addresses.
    def included_addresses=(new_addresses)
      @included_scan_targets[:addresses] = new_addresses
    end

    # Returns the array of IDs for included scan target asset groups.
    # @return [Array[Fixnum]] Array of included asset groups.
    def included_asset_groups
      @included_scan_targets[:asset_groups]
    end

    # Sets the array of IDs for included scan target asset groups.
    # @param [Array[Fixnum] new_asset_groups The new array of IDs for scan target asset groups.
    # @return [Array[Fixnum] Array of IDs of the updated scan target asset groups.
    def included_asset_groups=(new_asset_groups)
      @included_scan_targets[:asset_groups] = new_asset_groups
    end

    # Returns the array of excluded scan target addresses.
    # @return [Array[IPRange|HostName]] Array of excluded addresses.
    def excluded_addresses
      @excluded_scan_targets[:addresses]
    end

    # Sets the array of excluded scan target addresses.
    # @param [Array[IPRange|HostName]] new_addresses The new array of scan target addresses.
    # @return [Array[IPRange|HostName]] Array of updated scan target addresses.
    def excluded_addresses=(new_addresses)
      @excluded_scan_targets[:addresses] = new_addresses
    end

    # Returns the array of IDs for excluded scan target asset groups.
    # @return [Array[Fixnum]] Array of IDs for excluded asset groups.
    def excluded_asset_groups
      @excluded_scan_targets[:asset_groups]
    end

    # Sets the array IDs for excluded scan target asset groups.
    # @param [Array[Fixnum]] new_asset_groups The new array of IDs for scan target asset groups.
    # @return [Array[Fixnum]] Array of IDs of the updated scan target asset groups.
    def excluded_asset_groups=(new_asset_groups)
      @excluded_scan_targets[:asset_groups] = new_asset_groups
    end

    # Returns true when the site is dynamic.
    def is_dynamic?
      !@discovery_config.nil?
    end
    alias dynamic? is_dynamic?

    # Adds assets to this site by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def include_ip_range(from, to)
      from_ip = IPAddr.new(from)
      to_ip   = IPAddr.new(to)
      (from_ip..to_ip)
      raise 'Invalid IP range specified' if (from_ip..to_ip).to_a.size.zero?
      @included_scan_targets[:addresses] << IPRange.new(from, to)
    rescue ArgumentError => e
      raise "#{e.message} in given IP range"
    end

    # Remove assets to this site by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def remove_included_ip_range(from, to)
      from_ip = IPAddr.new(from)
      to_ip   = IPAddr.new(to)
      (from_ip..to_ip)
      raise 'Invalid IP range specified' if (from_ip..to_ip).to_a.size.zero?
      @included_scan_targets[:addresses].reject! { |t| t.eql? IPRange.new(from, to) }
    rescue ArgumentError => e
      raise "#{e.message} in given IP range"
    end

    # Adds an asset to this site included scan targets, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def include_asset(asset)
      @included_scan_targets[:addresses] << HostOrIP.convert(asset)
    end

    # Remove an asset to this site included scan targets, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def remove_included_asset(asset)
      @included_scan_targets[:addresses].reject! { |existing_asset| existing_asset == HostOrIP.convert(asset) }
    end

    # Adds assets to this site excluded scan targets by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def exclude_ip_range(from, to)
      from_ip = IPAddr.new(from)
      to_ip   = IPAddr.new(to)
      (from_ip..to_ip)
      raise 'Invalid IP range specified' if (from_ip..to_ip).to_a.size.zero?
      @excluded_scan_targets[:addresses] << IPRange.new(from, to)
    rescue ArgumentError => e
      raise "#{e.message} in given IP range"
    end

    # Remove assets from this site excluded scan targets by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def remove_excluded_ip_range(from, to)
      from_ip = IPAddr.new(from)
      to_ip   = IPAddr.new(to)
      (from_ip..to_ip)
      raise 'Invalid IP range specified' if (from_ip..to_ip).to_a.size.zero?
      @excluded_scan_targets[:addresses].reject! { |t| t.eql? IPRange.new(from, to) }
    rescue ArgumentError => e
      raise "#{e.message} in given IP range"
    end

    # Adds an asset to this site excluded scan targets, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def exclude_asset(asset)
      @excluded_scan_targets[:addresses] << HostOrIP.convert(asset)
    end

    # Removes an asset to this site excluded scan targets, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def remove_excluded_asset(asset)
      @excluded_scan_targets[:addresses].reject! { |existing_asset| existing_asset == HostOrIP.convert(asset) }
    end

    # Adds an asset group ID to this site included scan targets.
    #
    # @param [Integer] asset_group_id Identifier of an assetGroupID.
    #
    def include_asset_group(asset_group_id)
      validate_asset_group(asset_group_id)
      @included_scan_targets[:asset_groups] << asset_group_id.to_i
    end

    # Adds an asset group ID to this site included scan targets.
    #
    # @param [Integer] asset_group_id Identifier of an assetGroupID.
    #
    def remove_included_asset_group(asset_group_id)
      validate_asset_group(asset_group_id)
      @included_scan_targets[:asset_groups].reject! { |t| t.eql? asset_group_id.to_i }
    end

    # Adds an asset group ID to this site excluded scan targets.
    #
    # @param [Integer] asset_group_id Identifier of an assetGroupID.
    #
    def exclude_asset_group(asset_group_id)
      validate_asset_group(asset_group_id)
      @excluded_scan_targets[:asset_groups] << asset_group_id.to_i
    end

    # Adds an asset group ID to this site excluded scan targets.
    #
    # @param [Integer] asset_group_id Identifier of an assetGroupID.
    #
    def remove_excluded_asset_group(asset_group_id)
      validate_asset_group(asset_group_id)
      @excluded_scan_targets[:asset_groups].reject! { |t| t.eql? asset_group_id.to_i }
    end

    def validate_asset_group(asset_group_id)
      begin
        Integer(asset_group_id)
      rescue ArgumentError => e
        raise "Invalid asset_group id. #{e.message}"
      end

      raise 'Invalid asset_group id. Must be positive number.' if asset_group_id.to_i < 1
    end

    def add_user(user_id)
      unless user_id.is_a?(Numeric) && user_id > 0
        raise 'Invalid user id. A user id must be a positive number and refer to an existing system user.'
      end

      @users << { id: user_id }
    end

    def remove_user(user_id)
      unless user_id.is_a?(Numeric) && user_id > 0
        raise 'Invalid user id. A user id must be a positive number and refer to an existing system user.'
      end

      @users.delete_if { |h| h[:id] == user_id }
    end

    def self.from_hash(hash)
      site = new(hash[:name], hash[:scan_template_id])
      hash.each do |k, v|
        site.instance_variable_set("@#{k}", v)
      end

      # Convert each string address to either a HostName or IPRange object
      included_scan_targets = { addresses: [], asset_groups: [] }
      site.included_scan_targets[:addresses].each { |asset| included_scan_targets[:addresses] << HostOrIP.convert(asset) }
      included_scan_targets[:asset_groups] = site.included_scan_targets[:asset_groups]
      site.included_scan_targets = included_scan_targets

      excluded_scan_targets = { addresses: [], asset_groups: [] }
      site.excluded_scan_targets[:addresses].each { |asset| excluded_scan_targets[:addresses] << HostOrIP.convert(asset) }
      excluded_scan_targets[:asset_groups] = site.excluded_scan_targets[:asset_groups]
      site.excluded_scan_targets = excluded_scan_targets

      site
    end

    def to_json
      JSON.generate(to_h)
    end

    def to_h
      included_scan_targets = { addresses: @included_scan_targets[:addresses].compact,
                                asset_groups: @included_scan_targets[:asset_groups].compact }
      excluded_scan_targets = { addresses: @excluded_scan_targets[:addresses].compact,
                                asset_groups: @excluded_scan_targets[:asset_groups].compact }
      hash = { id: @id,
               name: @name,
               description: @description,
               auto_engine_selection_enabled: @auto_engine_selection_enabled,
               included_scan_targets: included_scan_targets,
               excluded_scan_targets: excluded_scan_targets,
               engine_id: @engine_id,
               scan_template_id: @scan_template_id,
               risk_factor: @risk_factor,
               schedules: (@schedules || []).map(&:to_h),
               shared_credentials: (@shared_credentials || []).map(&:to_h),
               site_credentials: (@site_credentials || []).map(&:to_h),
               web_credentials: (@web_credentials || []).map(&:to_h),
               discovery_config: @discovery_config.to_h,
               search_criteria: @search_criteria.to_h,
               tags: (@tags || []).map(&:to_h),
               alerts: (@alerts || []).map(&:to_h),
               organization: @organization.to_h,
               users: users }
      # @TODO: Revisit this for 2.0.0 update
      # Only pass in blackouts if they were actually specified (for backwards compatibility)
      hash[:blackouts] = @blackouts.map(&:to_h) if @blackouts && @blackouts.any?

      hash
    end

    require 'json'
    # Load an site from the provided console.
    #
    # @param [Connection] nsc Active connection to a Nexpose console.
    # @param [String] id Unique identifier of a site.
    # @return [Site] The requested site, if found.
    #
    def self.load(nsc, id)
      uri  = "/api/2.1/site_configurations/#{id}"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true)
      site = self.json_initializer(hash).deserialize(hash)

      # Convert each string address to either a HostName or IPRange object
      included_addresses = hash[:included_scan_targets][:addresses]
      site.included_scan_targets[:addresses] = []
      included_addresses.each { |asset| site.include_asset(asset) }

      excluded_addresses = hash[:excluded_scan_targets][:addresses]
      site.excluded_scan_targets[:addresses] = []
      excluded_addresses.each { |asset| site.exclude_asset(asset) }

      site.organization       = Organization.create(site.organization)
      site.schedules          = (hash[:schedules] || []).map { |schedule| Nexpose::Schedule.from_hash(schedule) }
      site.blackouts          = (hash[:blackouts] || []).map { |blackout| Nexpose::Blackout.from_hash(blackout) }
      site.site_credentials   = hash[:site_credentials].map { |cred| Nexpose::SiteCredentials.new.object_from_hash(nsc, cred) }
      site.shared_credentials = hash[:shared_credentials].map { |cred| Nexpose::SiteCredentials.new.object_from_hash(nsc, cred) }
      site.discovery_config   = Nexpose::DiscoveryConnection.new.object_from_hash(nsc, hash[:discovery_config]) unless hash[:discovery_config].nil?
      site.search_criteria    = Nexpose::DiscoveryConnection::Criteria.parseHash(hash[:search_criteria]) unless hash[:search_criteria].nil?
      site.alerts             = Alert.load_alerts(hash[:alerts])
      site.tags               = Tag.load_tags(hash[:tags])
      site.web_credentials = hash[:web_credentials].map { |web_cred| (
      web_cred[:service] == Nexpose::WebCredentials::WebAppAuthType::HTTP_HEADER ?
          Nexpose::WebCredentials::Headers.new(web_cred[:name], web_cred[:baseURL], web_cred[:soft403Pattern], web_cred[:id]).object_from_hash(nsc, web_cred) :
          Nexpose::WebCredentials::HTMLForms.new(web_cred[:name], web_cred[:baseURL], web_cred[:loginURL], web_cred[:soft403Pattern], web_cred[:id]).object_from_hash(nsc, web_cred)) }

      site
    end

    def self.json_initializer(data)
      new(data[:name], data[:scan_template_id])
    end

    # Copy an existing configuration from a Nexpose instance.
    # Returned object will reset the site ID and append "Copy" to the existing
    # name.
    #
    # @param [Connection] connection Connection to the security console.
    # @param [Fixnum] id Site ID of an existing site.
    # @return [Site] Site configuration loaded from a Nexpose console.
    #
    def self.copy(connection, id)
      site      = self.load(connection, id)
      site.id   = -1
      site.name = "#{site.name} Copy"
      site
    end

    # Saves this site to a Nexpose console.
    # If the site is dynamic, connection and asset filter changes must be
    # saved through the DiscoveryConnection#update_site call.
    #
    # @param [Connection] connection Connection to console where this site will be saved.
    # @return [Fixnum] Site ID assigned to this configuration, if successful.
    #
    def save(connection)
      new_site = @id == -1

      if new_site
        resp = AJAX.post(connection, '/api/2.1/site_configurations/', to_json, AJAX::CONTENT_TYPE::JSON)
        @id = resp.to_i
      else
        AJAX.put(connection, "/api/2.1/site_configurations/#{@id}", to_json, AJAX::CONTENT_TYPE::JSON)
      end

      # Retrieve the scan engine and shared credentials and add them to the site configuration
      site_config         = Site.load(connection, @id)
      @engine_id          = site_config.engine_id
      @shared_credentials = site_config.shared_credentials
      @alerts             = site_config.alerts

      @id
    end

    # Delete this site from a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this site will be saved.
    # @return [Boolean] Whether or not the site was successfully deleted.
    #
    def delete(connection)
      r = connection.execute(%(<SiteDeleteRequest session-id="#{connection.session_id}" site-id="#{@id}"/>))
      r.success
    end

    # Scan this site.
    #
    # @param [Connection] connection Connection to console where scan will be launched.
    # @param [String] sync_id Optional synchronization token.
    # @param [Boolean] blackout_override Optional. Given suffencent permissions, force bypass blackout and start scan.
    # @return [Scan] Scan launch information.
    #
    def scan(connection, sync_id = nil, blackout_override = false)
      xml = REXML::Element.new('SiteScanRequest')
      xml.add_attributes({ 'session-id' => connection.session_id,
                           'site-id' => @id,
                           'sync-id' => sync_id })

      xml.add_attributes({ 'force' => true }) if blackout_override
      response = connection.execute(xml, '1.1', timeout: connection.timeout)
      Scan.parse(response.res) if response.success
    end
  end

  # Object that represents the summary of a Nexpose Site.
  #
  class SiteSummary
    # The Site ID.
    attr_reader :id
    # The Site Name.
    attr_reader :name
    # A Description of the Site.
    attr_reader :description
    # User assigned risk multiplier.
    attr_reader :risk_factor
    # Current computed risk score for the site.
    attr_reader :risk_score

    # Constructor
    # SiteSummary(id, name, description, riskfactor = 1)
    def initialize(id, name, description = nil, risk_factor = 1.0, risk_score = 0.0)
      @id          = id
      @name        = name
      @description = description
      @risk_factor = risk_factor
      @risk_score  = risk_score
    end
  end

  # Object that represents a hostname to be added to a site.
  #
  class HostName
    # Named host (usually DNS or Netbios name).
    attr_accessor :host

    def initialize(hostname)
      @host = hostname
    end

    include Comparable

    def <=>(other)
      to_xml <=> other.to_xml
    end

    def eql?(other)
      to_xml == other.to_xml
    end

    def hash
      to_xml.hash
    end

    def as_xml
      xml = REXML::Element.new('host')
      xml.text = @host
      xml
    end
    alias to_xml_elem as_xml

    def to_xml
      to_xml_elem.to_s
    end

    def to_s
      @host.to_s
    end
  end

  # Object that represents a single IP address or an inclusive range of IP addresses.
  # If to is nil then the from field will be used to specify a single IP Address only.
  #
  class IPRange
    # Start of range *Required
    attr_accessor :from
    # End of range *Optional (If nil then IPRange is a single IP Address)
    attr_accessor :to

    # @overload initialize(ip)
    #   @param [#to_s] from the IP single IP address.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0')
    #
    # @overload initialize(start_ip, end_ip)
    #   @param [#to_s] from the IP to start the range with.
    #   @param [#to_s] to the IP to end the range with.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0', '192.168.1.255')
    #
    # @overload initialize(cidr_range)
    #   @param [#to_s] from the CIDR notation IP address range.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0/24')
    #   @note The range will not be stripped of reserved IP addresses (such as
    #     x.x.x.0 and x.x.x.255).
    #
    # @return [IPRange] an IP address range of one or more addresses.
    def initialize(from, to = nil)
      @from = from
      @to   = to unless from == to

      return unless @to.nil?

      range = IPAddr.new(@from.to_s).to_range
      unless range.one?
        @from = range.first.to_s
        @to   = range.last.to_s
      end
    end

    # Size of the IP range. The total number of IP addresses represented
    # by this range.
    #
    # @return [Fixnum] size of the range.
    #
    def size
      return 1 if @to.nil?
      from = IPAddr.new(@from)
      to   = IPAddr.new(@to)
      (from..to).to_a.size
    end

    include Comparable

    def <=>(other)
      return 1 unless other.respond_to? :from
      from    = IPAddr.new(@from)
      to      = @to.nil? ? from : IPAddr.new(@to)
      cf_from = IPAddr.new(other.from)
      cf_to   = IPAddr.new(other.to.nil? ? other.from : other.to)
      if cf_to < from
        1
      elsif to < cf_from
        -1
      else # Overlapping
        0
      end
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      return false unless other.respond_to? :from
      @from == other.from && @to == other.to
    end

    def include?(single_ip)
      return false unless single_ip.respond_to? :from
      from  = IPAddr.new(@from)
      to    = @to.nil? ? from : IPAddr.new(@to)
      other = IPAddr.new(single_ip)

      if other < from
        false
      elsif to < other
        false
      else
        true
      end
    end

    def hash
      to_xml.hash
    end

    def as_xml
      xml = REXML::Element.new('range')
      xml.add_attributes({ 'from' => @from, 'to' => @to })
      xml
    end
    alias to_xml_elem as_xml

    def to_xml
      as_xml.to_s
    end

    def to_s
      return from.to_s if to.nil?
      "#{from.to_s} - #{to.to_s}"
    end
  end
end
