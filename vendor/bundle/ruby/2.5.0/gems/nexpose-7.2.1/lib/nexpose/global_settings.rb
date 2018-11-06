module Nexpose
  # Object used to manage the global settings of a Nexpose console.
  #
  class GlobalSettings
    # IP addresses and/or host names that will be excluded from scanning across
    # all sites.
    attr_accessor :asset_exclusions

    # Whether asset linking in enabled.
    attr_accessor :asset_linking

    # Whether control scanning in enabled. A feature tied to ControlsInsight
    # integration.
    attr_accessor :control_scanning

    # XML document representing the entire configuration.
    attr_reader :xml

    # Private constructor. See #load method for retrieving a settings object.
    #
    def initialize(xml)
      @xml              = xml
      @asset_linking    = parse_asset_linking_from_xml(xml)
      @asset_exclusions = HostOrIP.parse(xml)
      @control_scanning = parse_control_scanning_from_xml(xml)
    end

    # Returns true if controls scanning is enabled.
    def control_scanning?
      control_scanning
    end

    # Save any updates to this settings object to the Nexpose console.
    #
    # @param [Connection] nsc Connection to a Nexpose console.
    # @return [Boolean] Whether saving was successful.
    #
    def save(nsc)
      # load method can return XML missing this required attribute.
      unless REXML::XPath.first(xml, '//*[@recalculation_duration]')
        risk_model = REXML::XPath.first(xml, '//riskModel')
        risk_model.add_attribute('recalculation_duration', 'do_not_recalculate')
      end

      replace_exclusions(xml, asset_exclusions)
      add_control_scanning_to_xml(xml, control_scanning)
      add_asset_linking_to_xml(xml, asset_linking)

      response = AJAX.post(nsc, '/data/admin/global-settings', xml)
      XMLUtils.success? response
    end

    # Add an asset exclusion setting.
    #
    # @param [IPRange|HostName|String] host_or_ip Host or IP (range) to exclude
    #   from scanning by the Nexpose console.
    #
    def add_exclusion(host_or_ip)
      asset = host_or_ip
      unless host_or_ip.respond_to?(:host) || host_or_ip.respond_to?(:from)
        asset = HostOrIP.convert(host_or_ip)
      end
      @asset_exclusions << asset
    end

    # Remove an asset exclusion setting.
    # If you need to remove a range of IPs, be sure to explicitly supply an
    # IPRange object to the method.
    #
    # @param [IPRange|HostName|String] host_or_ip Host or IP (range) to remove
    #   from the exclusion list.
    #
    def remove_exclusion(host_or_ip)
      asset = host_or_ip
      unless host_or_ip.respond_to?(:host) || host_or_ip.respond_to?(:from)
        # Attept to convert String to appropriate object.
        asset = HostOrIP.convert(host_or_ip)
      end
      @asset_exclusions = asset_exclusions.reject { |a| a.eql? asset }
    end

    # Load the global settings from a Nexpose console.
    #
    # @param [Connection] nsc Connection to a Nexpose console.
    # @return [GlobalSettings] Settings object for the console.
    #
    def self.load(nsc)
      response = AJAX.get(nsc, '/data/admin/global-settings')
      new(REXML::Document.new(response))
    end

    private

    # Internal method for updating exclusions before saving.
    def replace_exclusions(xml, exclusions)
      xml.elements.delete('//ExcludedHosts')
      elem = xml.root.add_element('ExcludedHosts')
      exclusions.each do |exclusion|
        elem.add_element(exclusion.as_xml)
      end
    end

    # Internal method for parsing XML for whether control scanning in enabled.
    def parse_control_scanning_from_xml(xml)
      enabled = false
      if elem = REXML::XPath.first(xml, '//enableControlsScan[@enabled]')
        enabled = elem.attribute('enabled').value.to_i == 1
      end
      enabled
    end

    # Internal method for updating control scanning before saving.
    def add_control_scanning_to_xml(xml, enabled)
      if elem = REXML::XPath.first(xml, '//enableControlsScan')
        elem.attributes['enabled'] = enabled ? '1' : '0'
      else
        elem = REXML::Element.new('ControlsScan', xml.root)
        elem.add_element('enableControlsScan',
                         'enabled' => enabled ? '1' : '0')
      end
    end

    # Internal method for parsing XML for whether asset linking in enabled.
    def parse_asset_linking_from_xml(xml)
      enabled = true
      if elem = REXML::XPath.first(xml, '//AssetCorrelation[@enabled]')
        enabled = elem.attribute('enabled').value.to_i == 1
      end
      enabled
    end

    # Internal method for updating asset linking before saving.
    def add_asset_linking_to_xml(xml, enabled)
      elem = REXML::XPath.first(xml, '//AssetCorrelation')
      return nil unless elem

      elem.attributes['enabled'] = enabled ? '1' : '0'
    end
  end
end
