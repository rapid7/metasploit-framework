module Nexpose
  module_function

  class Connection
    # Lists all tags
    #
    # @return [Array[TagSummary]] List of current tags.
    #
    def tags
      tag_summary = []
      tags        = JSON.parse(AJAX.get(self, '/api/2.0/tags', AJAX::CONTENT_TYPE::JSON, { per_page: 2_147_483_647 }))
      tags['resources'].each do |json|
        tag_summary << TagSummary.parse(json)
      end
      tag_summary
    end
    alias list_tags tags

    # Deletes a tag by ID
    #
    # @param [Fixnum] tag_id ID of tag to delete
    #
    def delete_tag(tag_id)
      AJAX.delete(self, "/api/2.0/tags/#{tag_id}")
    end

    # Lists all the tags on an asset
    #
    # @param [Fixnum] asset_id of the asset to list the applied tags for
    # @return [Array[TagSummary]] list of tags on asset
    #
    def asset_tags(asset_id)
      tag_summary = []
      asset_tag   = JSON.parse(AJAX.get(self, "/api/2.0/assets/#{asset_id}/tags", AJAX::CONTENT_TYPE::JSON, { per_page: 2_147_483_647 }))
      asset_tag['resources'].select { |r| r['asset_ids'].find { |i| i == asset_id } }.each do |json|
        tag_summary << TagSummary.parse(json)
      end
      tag_summary
    end
    alias list_asset_tags asset_tags

    # Removes a tag from an asset
    #
    # @param [Fixnum] asset_id on which to remove tag
    # @param [Fixnum] tag_id to remove from asset
    #
    def remove_tag_from_asset(asset_id, tag_id)
      AJAX.delete(self, "/api/2.0/assets/#{asset_id}/tags/#{tag_id}")
    end

    # Lists all the tags on a site
    #
    # @param [Fixnum] site_id id of the site to get the applied tags
    # @return [Array[TagSummary]] list of tags on site
    #
    def site_tags(site_id)
      tag_summary = []
      site_tag = JSON.parse(AJAX.get(self, "/api/2.0/sites/#{site_id}/tags", AJAX::CONTENT_TYPE::JSON, { per_page: 2_147_483_647 }))
      site_tag['resources'].each do |json|
        tag_summary << TagSummary.parse(json)
      end
      tag_summary
    end
    alias list_site_tags site_tags

    # Removes a tag from a site
    #
    # @param [Fixnum] site_id id of the site on which to remove the tag
    # @param [Fixnum] tag_id id of the tag to remove
    #
    def remove_tag_from_site(site_id, tag_id)
      AJAX.delete(self, "/api/2.0/sites/#{site_id}/tags/#{tag_id}")
    end

    # Lists all the tags on an asset_group
    #
    # @param [Fixnum] asset_group_id id of the group on which tags are listed
    # @return [Array[TagSummary]] list of tags on asset group
    #
    def asset_group_tags(asset_group_id)
      tag_summary = []
      asset_group_tag = JSON.parse(AJAX.get(self, "/api/2.0/asset_groups/#{asset_group_id}/tags", AJAX::CONTENT_TYPE::JSON, { per_page: 2_147_483_647 }))
      asset_group_tag['resources'].each do |json|
        tag_summary << TagSummary.parse(json)
      end
      tag_summary
    end
    alias group_tags asset_group_tags
    alias list_asset_group_tags asset_group_tags

    # Removes a tag from an asset_group
    #
    # @param [Fixnum] asset_group_id id of group on which to remove tag
    # @param [Fixnum] tag_id of the tag to remove from asset group
    #
    def remove_tag_from_asset_group(asset_group_id, tag_id)
      AJAX.delete(self, "/api/2.0/asset_groups/#{asset_group_id}/tags/#{tag_id}")
    end
    alias remove_tag_from_group remove_tag_from_asset_group

    # Returns the criticality value which takes precedent for an asset
    #
    # @param [Fixnum] asset_id id of asset on which criticality tag is selected
    # @return [String] selected_criticality string of the relevant criticality; nil if not tagged
    #
    def selected_criticality_tag(asset_id)
      selected_criticality = AJAX.get(self, "/data/asset/#{asset_id}/selected-criticality-tag")
      selected_criticality.empty? ? nil : JSON.parse(selected_criticality)['name']
    end
  end

  # Summary value object for tag information
  #
  class TagSummary

    # ID of tag
    attr_accessor :id

    # Name of tag
    attr_accessor :name

    # One of Tag::Type::Generic
    attr_accessor :type

    def initialize(name, type, id)
      @name = name
      @type = type
      @id   = id
    end

    def self.parse(json)
      new(json['tag_name'], json['tag_type'], json['tag_id'])
    end

    def self.parse_xml(xml)
      new(xml.attributes['name'], xml.attributes['type'], xml.attributes['id'].to_i)
    end

    # XML representation of the tag summary as required by Site and AssetGroup
    #
    # @return [ELEMENT] XML element

    def as_xml
      xml = REXML::Element.new('Tag')
      xml.add_attribute('id', @id)
      xml.add_attribute('name', @name)
      xml.add_attribute('type', @type)
      xml
    end
  end

  # Tag object containing tag details
  #
  class Tag < TagSummary
    module Type
      # Criticality tag types
      module Level
        VERY_HIGH = 'Very High'
        HIGH      = 'High'
        MEDIUM    = 'Medium'
        LOW       = 'Low'
        VERY_LOW  = 'Very Low'
      end

      # Tag types
      module Generic
        CUSTOM      = 'CUSTOM'
        OWNER       = 'OWNER'
        LOCATION    = 'LOCATION'
        CRITICALITY = 'CRITICALITY'
      end

      module Color
        BLUE    = '#496a77'
        DEFAULT = '#f6f6f6'
        GREEN   = '#7d8a58'
        ORANGE  = '#de7200'
        PURPLE  = '#844f7d'
        RED     = '#a0392e'
      end
    end

    # Creation source
    attr_accessor :source

    # HEX color code of tag
    attr_reader :color

    # Risk modifier
    attr_accessor :risk_modifier

    # Array containing Site IDs to be associated with tag
    attr_accessor :site_ids

    # Array containing Asset IDs to be associated with tag
    attr_accessor :asset_ids

    # Array containing Asset IDs directly associated with the tag
    attr_accessor :associated_asset_ids

    # Array containing Asset Group IDs to be associated with tag
    attr_accessor :asset_group_ids
    alias group_ids asset_group_ids
    alias group_ids= asset_group_ids=

    # A TagCriteria
    attr_accessor :search_criteria

    def initialize(name, type, id = -1)
      @name   = name
      @type   = type
      @id     = id
      @source = 'nexpose-client'
      @color  = @type == Type::Generic::CUSTOM ? Type::Color::DEFAULT : nil
    end

    # Set the color but validate it
    def color=(hex)
      valid_colors = Type::Color.constants.map { |c| Type::Color.const_get(c) }
      unless hex.nil? || valid_colors.include?(hex.to_s.downcase)
        raise ArgumentError, "Unable to set color to an invalid color.\nUse one of #{valid_colors}"
      end

      @color = hex
    end

    # Create list of tag objects from hash
    def self.load_tags(tags)
      unless tags.nil?
        tags = tags.map do |hash|
          self.create(hash)
        end
      end
      tags
    end

    # Create tag object from hash
    def self.create(hash)
      attributes = hash[:attributes]
      color      = attributes.find { |attr| attr[:tag_attribute_name] == 'COLOR' }
      color      = color[:tag_attribute_value] if color
      source     = attributes.find { |attr| attr[:tag_attribute_name] == 'SOURCE' }
      source     = source[:tag_attribute_value] if source
      tag        = Tag.new(hash[:tag_name], hash[:tag_type], hash[:tag_id])
      tag.color  = color
      tag.source = source
      tag
    end

    def to_h
      {
        tag_id: id,
        tag_name: name,
        tag_type: type,
        attributes: [
          { tag_attribute_name: 'COLOR', tag_attribute_value: color },
          { tag_attribute_name: 'SOURCE', tag_attribute_value: source }
        ]
      }
    end

    # Creates and saves a tag to Nexpose console
    #
    # @param [Connection] connection Nexpose connection
    # @return [Fixnum] ID of saved tag
    #
    def save(connection)
      params = to_json
      if @id == -1
        uri = AJAX.post(connection, '/api/2.0/tags', params, AJAX::CONTENT_TYPE::JSON)
        @id = uri.split('/').last.to_i
      else
        AJAX.put(connection, "/api/2.0/tags/#{@id}", params, AJAX::CONTENT_TYPE::JSON)
      end
      @id
    end

    # Retrieve detailed description of a single tag
    #
    # @param [Connection] connection Nexpose connection
    # @param [Fixnum] tag_id ID of tag to retrieve
    # @return [Tag] requested tag
    #
    def self.load(connection, tag_id)
      json = JSON.parse(AJAX.get(connection, "/api/2.0/tags/#{tag_id}"))
      Tag.parse(json)
    end

    def to_json
      json = { 'tag_name' => @name,
               'tag_type' => @type,
               'tag_id' => @id,
               'attributes' => [{ 'tag_attribute_name' => 'SOURCE',
                                  'tag_attribute_value' => @source }],
               'tag_config' => { 'site_ids' => @site_ids,
                                 'tag_associated_asset_ids' => @associated_asset_ids,
                                 'asset_group_ids' => @asset_group_ids,
                                 'search_criteria' => @search_criteria ? @search_criteria.to_h : nil } }
      if @type == Type::Generic::CUSTOM
        json['attributes'] << { 'tag_attribute_name' => 'COLOR', 'tag_attribute_value' => @color }
      end
      JSON.generate(json)
    end

    # Delete this tag from Nexpose console
    #
    # @param [Connection] connection Nexpose connection
    #
    def delete(connection)
      connection.delete_tag(@id)
    end

    def self.parse(json)
      color         = json['attributes'].find { |attr| attr['tag_attribute_name'] == 'COLOR' }
      color         = color['tag_attribute_value'] if color
      source        = json['attributes'].find { |attr| attr['tag_attribute_name'] == 'SOURCE' }
      source        = source['tag_attribute_value'] if source
      tag           = Tag.new(json['tag_name'], json['tag_type'], json['tag_id'])
      tag.color     = color
      tag.source    = source
      tag.asset_ids = json['asset_ids']
      if json['tag_config']
        tag.site_ids             = json['tag_config']['site_ids']
        tag.associated_asset_ids = json['tag_config']['tag_associated_asset_ids']
        tag.asset_group_ids      = json['tag_config']['asset_group_ids']
        criteria                 = json['tag_config']['search_criteria']
        tag.search_criteria      = criteria ? Criteria.parse(criteria) : nil
      end
      modifier = json['attributes'].find { |attr| attr['tag_attribute_name'] == 'RISK_MODIFIER' }
      tag.risk_modifier = modifier['tag_attribute_value'].to_i if modifier
      tag
    end

    # Adds a tag to an asset
    #
    # @param [Connection] connection Nexpose connection
    # @param [Fixnum] asset_id of the asset to be tagged
    # @return [Fixnum] ID of applied tag
    #
    def add_to_asset(connection, asset_id)
      params = to_json_for_add
      url    = "/api/2.0/assets/#{asset_id}/tags"
      uri    = AJAX.post(connection, url, params, AJAX::CONTENT_TYPE::JSON)
      @id    = uri.split('/').last.to_i
    end

    # Adds a tag to a site
    #
    # @param [Connection] connection Nexpose connection
    # @param [Fixnum] site_id of the site to be tagged
    # @return [Fixnum] ID of applied tag
    #
    def add_to_site(connection, site_id)
      params = to_json_for_add
      url    = "/api/2.0/sites/#{site_id}/tags"
      uri    = AJAX.post(connection, url, params, AJAX::CONTENT_TYPE::JSON)
      @id    = uri.split('/').last.to_i
    end

    # Adds a tag to an asset group
    #
    # @param [Connection] connection Nexpose connection
    # @param [Fixnum] group_id id of the asset group to be tagged
    # @return [Fixnum] ID of applied tag
    #
    def add_to_group(connection, group_id)
      params = to_json_for_add
      url    = "/api/2.0/asset_groups/#{group_id}/tags"
      uri    = AJAX.post(connection, url, params, AJAX::CONTENT_TYPE::JSON)
      @id    = uri.split('/').last.to_i
    end
    alias add_to_asset_group add_to_group

    private

    def to_json_for_add
      if @id == -1
        json = { 'tag_name' => @name,
                 'tag_type' => @type,
                 'attributes' => [{ 'tag_attribute_name' => 'SOURCE',
                                    'tag_attribute_value' => @source }] }
        if @type == Tag::Type::Generic::CUSTOM
          json['attributes'] << { 'tag_attribute_name' => 'COLOR',
                                  'tag_attribute_value' => @color }
        end
        params = JSON.generate(json)
      else
        params = JSON.generate('tag_id' => @id)
      end
      params
    end
  end
end
