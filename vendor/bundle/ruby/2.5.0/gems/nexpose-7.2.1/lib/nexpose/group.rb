module Nexpose

  class Connection
    include XMLUtils

    # Delete an asset group and all associated data.
    #
    # @param [Fixnum] id Asset group ID to delete.
    #
    # @return [Boolean] Whether group deletion succeeded.
    #
    def delete_asset_group(id)
      r = execute(make_xml('AssetGroupDeleteRequest', { 'group-id' => id }))
      r.success
    end

    alias delete_group delete_asset_group

    # Retrieve an array of all asset groups the user is authorized to view or
    # manage.
    #
    # @return [Array[AssetGroupSummary]] Array of AssetGroupSummary objects.
    #
    def list_asset_groups
      r = execute(make_xml('AssetGroupListingRequest'))
      groups = []
      if r.success
        r.res.elements.each('AssetGroupListingResponse/AssetGroupSummary') do |group|
          groups << AssetGroupSummary.new(group.attributes['id'].to_i,
                                          group.attributes['name'],
                                          group.attributes['description'],
                                          group.attributes['riskscore'].to_f,
                                          group.attributes['dynamic'].to_i == 1)
        end
      end
      groups
    end

    alias groups list_asset_groups
    alias asset_groups list_asset_groups
  end

  # Summary value object for asset group information.
  #
  class AssetGroupSummary
    attr_reader :id, :name, :description, :risk_score, :dynamic

    def initialize(id, name, desc, risk, dynamic)
      @id          = id
      @name        = name
      @description = desc
      @risk_score  = risk
      @dynamic     = dynamic
    end

    def dynamic?
      dynamic
    end

    # Delete this asset group and all associated data.
    #
    # @param [Connection] connection Connection to security console.
    #
    def delete(connection)
      connection.delete_asset_group(@id)
    end
  end

  # Asset group configuration object containing Device details.
  #
  class AssetGroup < AssetGroupSummary
    include Sanitize

    attr_accessor :name, :description, :id, :tags

    # Array[Device] of devices associated with this asset group.
    attr_accessor :assets
    alias devices assets
    alias devices= assets=

    def initialize(name, desc, id = -1, risk = 0.0)
      @name        = name
      @description = desc
      @id          = id
      @risk_score  = risk
      @assets      = []
      @tags        = []
    end

    def save(connection)
      xml = "<AssetGroupSaveRequest session-id='#{connection.session_id}'>"
      xml << to_xml
      xml << '</AssetGroupSaveRequest>'
      res = connection.execute(xml)
      @id = res.attributes['group-id'].to_i if res.success && @id < 1
    end

    # Generate an XML representation of this group configuration
    #
    # @return [String] XML valid for submission as part of other requests.
    #
    def as_xml
      xml = REXML::Element.new('AssetGroup')
      xml.attributes['id']          = @id
      xml.attributes['name']        = @name
      xml.attributes['description'] = @description

      if @description && !@description.empty?
        elem = REXML::Element.new('Description')
        elem.add_text(@description)
        xml.add_element(elem)
      end

      elem = REXML::Element.new('Devices')
      @assets.each { |a| elem.add_element('device', { 'id' => a.id }) }
      xml.add_element(elem)

      unless tags.empty?
        tag_xml = xml.add_element(REXML::Element.new('Tags'))
        @tags.each { |tag| tag_xml.add_element(tag.as_xml) }
      end

      xml
    end

    # Get an XML representation of the group that is valid for a save request.
    # Note that only name, description, and asset ID information is accepted
    # by a save request.
    #
    # @return [String] XML representation of the asset group.
    #
    def to_xml
      as_xml.to_s
    end

    # Launch ad hoc scans against each group of assets per site.
    #
    # @param [Connection] connection Connection to console where asset group
    #   is configured.
    # @return [Hash] Hash of site ID to Scan launch information for each scan.
    #
    def rescan_assets(connection)
      scans     = {}
      sites_ids = @assets.map(&:site_id).uniq
      sites_ids.each do |site_id|
        to_scan = @assets.select { |d| d.site_id == site_id }
        scans[site_id] = connection.scan_devices(to_scan)
      end
      scans
    end

    # Load an existing configuration from a Nexpose instance.
    #
    # @param [Connection] connection Connection to console where asset group
    #   is configured.
    # @param [Fixnum] id Asset group ID of an existing group.
    # @return [AssetGroup] Asset group configuration loaded from a Nexpose
    #   console.
    #
    def self.load(connection, id)
      xml = %(<AssetGroupConfigRequest session-id="#{connection.session_id}" group-id="#{id}"/>)
      r   = APIRequest.execute(connection.url, xml, '1.1', { timeout: connection.timeout, open_timeout: connection.open_timeout })
      parse(r.res)
    end

    def self.parse(xml)
      return nil unless xml
      group = REXML::XPath.first(xml, 'AssetGroupConfigResponse/AssetGroup')
      asset_group = new(group.attributes['name'],
                        group.attributes['description'],
                        group.attributes['id'].to_i,
                        group.attributes['riskscore'].to_f)

      group.elements.each('Description') do |desc|
        asset_group.description = desc.text
      end

      group.elements.each('Devices/device') do |dev|
        asset_group.assets << Device.new(dev.attributes['id'].to_i,
                                         dev.attributes['address'],
                                         dev.attributes['site-id'].to_i,
                                         dev.attributes['riskfactor'].to_f,
                                         dev.attributes['riskscore'].to_f)
      end
      group.elements.each('Tags/Tag') do |tag|
        asset_group.tags << TagSummary.parse_xml(tag)
      end
      asset_group
    end
  end
end
