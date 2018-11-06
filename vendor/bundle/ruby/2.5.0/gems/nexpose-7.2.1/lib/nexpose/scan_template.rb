module Nexpose

  class Connection

    # List the scan templates currently configured on the console.
    #
    # @return [Array[ScanTemplateSummary]] list of scan template summary objects.
    #
    def list_scan_templates
      templates = JSON.parse(AJAX.get(self, '/api/2.0/scan_templates'))
      templates['resources'].map { |t| ScanTemplateSummary.new(t) }
    end

    alias scan_templates list_scan_templates

    # Delete a scan template from the console.
    # Cannot be used to delete a built-in template.
    #
    # @param [String] id Unique identifier of an existing scan template.
    #
    def delete_scan_template(id)
      AJAX.delete(self, "/data/scan/templates/#{URI.encode(id)}")
    end
  end

  # Scan Template summary information. Used when retrieving basic information about
  # all scan templates.
  #
  class ScanTemplateSummary
    attr_reader :name, :id

    def initialize(json)
      @name = json['name']
      @id   = json['id']
    end
  end

  # Configuration object for a scan template.
  #
  # The constructor is designed to take a valid XML representation of a scan
  # template. If you wish to create a new scan template from scratch, use the
  # #load method without a template ID. If you wish to copy and modify an
  # existing template, use the #copy method.
  #
  # This class is only a partial representation of some of the features
  # available for configuration.
  #
  class ScanTemplate
    include Sanitize

    # Parsed XML of a scan template.
    attr_reader :xml

    # @param [String] xml XML representation of a scan template.
    def initialize(xml)
      @xml = REXML::Document.new(xml)
    end

    # @return [String] Unique identifier of the scan template.
    def id
      root = REXML::XPath.first(@xml, 'ScanTemplate')
      root.attributes['id']
    end

    def id=(value)
      root = REXML::XPath.first(@xml, 'ScanTemplate')
      root.attributes['id'] = value
    end

    # @return [String] Name or title of this scan template.
    def name
      desc = REXML::XPath.first(@xml, 'ScanTemplate/templateDescription')
      desc.nil? ? nil : desc.attributes['title']
    end

    # Assign name to this scan template. Required attribute.
    # @param [String] name Title to assign.
    def name=(name)
      desc = REXML::XPath.first(@xml, 'ScanTemplate/templateDescription')
      if desc
        desc.attributes['title'] = replace_entities(name)
      else
        root = REXML::XPath.first(xml, 'ScanTemplate')
        desc = REXML::Element.new('templateDescription')
        desc.add_attribute('title', name)
        root.add_element(desc)
      end
    end

    # @return [String] Description of this scan template.
    def description
      desc = REXML::XPath.first(@xml, 'ScanTemplate/templateDescription')
      desc.nil? ? nil : desc.text.to_s
    end

    # Assign a description to this scan template. Require attribute.
    # @param [String] description Description of the scan template.
    def description=(description)
      desc = REXML::XPath.first(@xml, 'ScanTemplate/templateDescription')
      if desc
        desc.text = replace_entities(description)
      else
        root = REXML::XPath.first(xml, 'ScanTemplate')
        desc = REXML::Element.new('templateDescription')
        desc.add_text(description)
        root.add_element(desc)
      end
    end

    # @return [Boolean] Whether control scanning in enabled.
    def control_scanning?
      global_controls_scan = REXML::XPath.first(@xml, 'ScanTemplate/ControlsScan/globalControlsScanEnabled')
      local_controls_scan  = REXML::XPath.first(@xml, 'ScanTemplate/ControlsScan/localControlsScanEnabled')

      global_controls_scan.attributes['enabled'] == '1' || local_controls_scan.attributes['enabled'] == '1'
    end

    # Adjust whether to perform control scanning (ControlsInsight integration)
    # with this template.
    # @param [Boolean] enable Whether to turn on control scanning.
    def control_scanning=(enable)
      local_controls_scan = REXML::XPath.first(@xml, 'ScanTemplate/ControlsScan/localControlsScanEnabled')
      local_controls_scan.attributes['enabled'] = enable ? '1' : '0'
    end

    # @return [Boolean] Whether vuln scanning in enabled.
    def vuln_scanning?
      gen = REXML::XPath.first(@xml, 'ScanTemplate/General')
      gen.attributes['disableVulnScan'] == '0'
    end

    # Adjust whether to perform vuln scanning with this template.
    # @param [Boolean] enable Whether to turn on vuln scanning.
    def vuln_scanning=(enable)
      gen = REXML::XPath.first(@xml, 'ScanTemplate/General')
      gen.attributes['disableVulnScan'] = enable ? '0' : '1'
    end

    # @return [Boolean] Whether policy scanning in enabled.
    def policy_scanning?
      gen = REXML::XPath.first(@xml, 'ScanTemplate/General')
      gen.attributes['disablePolicyScan'] == '0'
    end

    # Adjust whether to perform policy scanning with this template.
    # @param [Boolean] enable Whether to turn on policy scanning.
    def policy_scanning=(enable)
      gen = REXML::XPath.first(@xml, 'ScanTemplate/General')
      gen.attributes['disablePolicyScan'] = enable ? '0' : '1'
    end

    # @return [Boolean] Whether web spidering in enabled.
    def web_spidering?
      gen = REXML::XPath.first(@xml, 'ScanTemplate/General')
      gen.attributes['disableWebSpider'] == '0'
    end

    # Adjust whether to perform web spidering with this template.
    # @param [Boolean] enable Whether to turn on web spider scanning.
    def web_spidering=(enable)
      gen = REXML::XPath.first(@xml, 'ScanTemplate/General')
      gen.attributes['disableWebSpider'] = enable ? '0' : '1'
    end

    # Adjust the number of threads to use per scan engine for this template
    # @param [Integer] threads the number of threads to use per engine
    def scan_threads=(threads)
      scan_threads = REXML::XPath.first(@xml, 'ScanTemplate/General/scanThreads')
      scan_threads.text = threads.to_s
    end

    # Adjust the number of threads to use per asset for this template
    # @param [Integer] threads the number of threads to use per asset
    def host_threads=(threads)
      host_threads = REXML::XPath.first(@xml, 'ScanTemplate/General/hostThreads')
      host_threads.text = threads.to_s
    end

    # Enable/disable IP stack fingerprinting
    # @param [Boolean] enable Enable or disable IP stack fingerprinting
    def enable_ip_stack_fingerprinting=(enable)
      ns = REXML::XPath.first(@xml, 'ScanTemplate/Plugins/Plugin[@name="java/NetworkScanners"]')
      param = REXML::XPath.first(ns, './param[@name="ipFingerprintEnabled"]')
      if param
        param.text = (enable ? 1 : 0)
      else
        param = REXML::Element.new('param')
        param.add_attribute('name', 'ipFingerprintEnabled')
        param.text = (enable ? 1 : 0)
        ns.add_element(param)
      end
    end

    # Enable/disable ICMP device discovery
    # @param [Boolean] enable Enable or disable ICMP device discovery
    def enable_icmp_device_discovery=(enable)
      icmp = REXML::XPath.first(@xml, 'ScanTemplate/DeviceDiscovery/CheckHosts/icmpHostCheck')
      icmp.attributes['enabled'] = (enable ? 1 : 0)
    end

    # Enable/disable TCP device discovery
    # @param [Boolean] enable Enable or disable TCP device discovery
    def enable_tcp_device_discovery=(enable)
      tcp = REXML::XPath.first(@xml, 'ScanTemplate/DeviceDiscovery/CheckHosts/TCPHostCheck')
      tcp.attributes['enabled'] = (enable ? 1 : 0)
    end

    # Set custom TCP ports to scan for device discovery
    # @param [Array] ports Ports to scan for device discovery
    def tcp_device_discovery_ports=(ports)
      tcp = REXML::XPath.first(@xml, 'ScanTemplate/DeviceDiscovery/CheckHosts/TCPHostCheck')
      REXML::XPath.first(tcp, './portList').text = ports.join(',')
    end

    # Enable/disable UDP device discovery
    # @param [Boolean] enable Enable or disable UDP device discovery
    def enable_udp_device_discovery=(enable)
      udp = REXML::XPath.first(@xml, 'ScanTemplate/DeviceDiscovery/CheckHosts/UDPHostCheck')
      udp.attributes['enabled'] = (enable ? 1 : 0)
    end

    # Set custom UDP ports to scan for UDP device discovery
    # @param [Array] ports Ports to scan for UDP device discovery
    def udp_device_discovery_ports=(ports)
      udp = REXML::XPath.first(@xml, 'ScanTemplate/DeviceDiscovery/CheckHosts/UDPHostCheck')
      REXML::XPath.first(udp, './portList').text = ports.join(',')
    end

    # Enable or disable TCP port scanning.
    # @param [Boolean] enable Enable or disable TCP ports
    def enable_tcp_service_discovery=(enable)
      service_ports = REXML::XPath.first(@xml, 'ScanTemplate/ServiceDiscovery/TCPPortScan')
      service_ports.attributes['mode'] = 'none' unless enable
    end

    # Set custom TCP ports to scan for TCP service discovery
    # @param [Array] ports Ports to scan for TCP service discovery
    def tcp_service_discovery_ports=(ports)
      service_ports = REXML::XPath.first(@xml, 'ScanTemplate/ServiceDiscovery/TCPPortScan')
      service_ports.attributes['mode'] = 'custom'
      service_ports.attributes['method'] = 'syn'
      REXML::XPath.first(service_ports, './portList').text = ports.join(',')
    end

    # Exclude TCP ports during TCP service discovery
    # @param [Array] ports TCP ports to exclude from TCP service discovery
    def exclude_tcp_service_discovery_ports=(ports)
      service_ports = REXML::XPath.first(@xml, 'ScanTemplate/ServiceDiscovery/ExcludedTCPPortScan')
      REXML::XPath.first(service_ports, './portList').text = ports.join(',')
    end

    # Set custom UDP ports to scan for UDP service discovery
    # @param [Array] ports Ports to scan during UDP service discovery
    def udp_service_discovery_ports=(ports)
      service_ports = REXML::XPath.first(@xml, 'ScanTemplate/ServiceDiscovery/UDPPortScan')
      service_ports.attributes['mode'] = 'custom'
      REXML::XPath.first(service_ports, './portList').text = ports.join(',')
    end

    # Exclude UDP ports when performing UDP service discovery
    # @param [Array] ports UDP ports to exclude from UDP service discovery
    def exclude_udp_service_discovery_ports=(ports)
      service_ports = REXML::XPath.first(@xml, 'ScanTemplate/ServiceDiscovery/ExcludedUDPPortScan')
      REXML::XPath.first(service_ports, './portList').text = ports.join(',')
    end

    # Enable or disable UDP service discovery
    # @param [Boolean] enable Enable or disable UDP service discovery
    def enable_udp_service_discovery=(enable)
      service_ports = REXML::XPath.first(@xml, 'ScanTemplate/ServiceDiscovery/UDPPortScan')
      service_ports.attributes['mode'] = 'none' unless enable
    end

    # @return [Boolean] Whether to correlate reliable checks with regular checks.
    def correlate?
      vuln_checks = REXML::XPath.first(@xml, 'ScanTemplate/VulnerabilityChecks')
      vuln_checks.attributes['correlate'] == '1'
    end

    # Adjust whether to correlate reliable checks with regular checks.
    # @param [Boolean] enable Whether to turn on vulnerability correlation.
    def correlate=(enable)
      vuln_checks = REXML::XPath.first(@xml, 'ScanTemplate/VulnerabilityChecks')
      vuln_checks.attributes['correlate'] = enable ? '1' : '0'
    end

    # @return [Boolean] Whether unsafe vulnerability checks are performed
    #   by this template.
    def unsafe_checks?
      checks = REXML::XPath.first(@xml, 'ScanTemplate/VulnerabilityChecks')
      checks.attributes['unsafe'] == '1'
    end

    # Adjust whether to perform unsafe vulnerability checks with this template.
    # @param [Boolean] enable Whether to turn on unsafe checks.
    def unsafe_checks=(enable)
      checks = REXML::XPath.first(@xml, 'ScanTemplate/VulnerabilityChecks')
      checks.attributes['unsafe'] = enable ? '1' : '0'
    end

    # @return [Boolean] Whether potential vulnerability checks are performed
    #   with this template.
    def potential_checks?
      checks = REXML::XPath.first(@xml, 'ScanTemplate/VulnerabilityChecks')
      checks.attributes['potential'] == '1'
    end

    # Adjust whether to perform potential vulnerability checks with this template.
    # @param [Boolean] enable Whether to turn on potential checks.
    def potential_checks=(enable)
      checks = REXML::XPath.first(@xml, 'ScanTemplate/VulnerabilityChecks')
      checks.attributes['potential'] = enable ? '1' : '0'
    end

    # Get a list of the check categories disabled for this scan template.
    #
    # @return [Array[String]] List of enabled categories.
    #
    def disabled_checks_by_category
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks/Disabled')
      checks ? checks.elements.to_a('VulnCategory').map { |c| c.attributes['name'] } : []
    end

    # Get a list of the check categories enabled for this scan template.
    #
    # @return [Array[String]] List of enabled categories.
    #
    def enabled_checks_by_category
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks/Enabled')
      checks ? checks.elements.to_a('VulnCategory').map { |c| c.attributes['name'] } : []
    end

    # Enable checks by category for this template.
    #
    # @param [String] category Category to enable. @see #list_vuln_categories
    #
    def enable_checks_by_category(category)
      _enable_check(category, 'VulnCategory')
    end

    # Disable checks by category for this template.
    #
    # @param [String] category Category to disable. @see #list_vuln_categories
    #
    def disable_checks_by_category(category)
      _disable_check(category, 'VulnCategory')
    end

    # Remove checks by category for this template. Removes both enabled and
    # disabled checks.
    #
    # @param [String] category Category to remove. @see #list_vuln_categories
    #
    def remove_checks_by_category(category)
      _remove_check(category, 'VulnCategory')
    end

    # Get a list of the check types disabled for this scan template.
    #
    # @return [Array[String]] List of enabled check types.
    #
    def disabled_checks_by_type
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks/Disabled')
      checks ? checks.elements.to_a('CheckType').map { |c| c.attributes['name'] } : []
    end

    # Get a list of the check types enabled for this scan template.
    #
    # @return [Array[String]] List of enabled check types.
    #
    def enabled_checks_by_type
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks/Enabled')
      checks ? checks.elements.to_a('CheckType').map { |c| c.attributes['name'] } : []
    end

    # Enable checks by type for this template.
    #
    # @param [String] type Type to enable. @see #list_vuln_types
    #
    def enable_checks_by_type(type)
      _enable_check(type, 'CheckType')
    end

    # Disable checks by type for this template.
    #
    # @param [String] type Type to disable. @see #list_vuln_types
    #
    def disable_checks_by_type(type)
      _disable_check(type, 'CheckType')
    end

    # Remove checks by type for this template. Removes both enabled and
    # disabled checks.
    #
    # @param [String] type Type to remove. @see #list_vuln_types
    #
    def remove_checks_by_type(type)
      _remove_check(type, 'CheckType')
    end

    def _enable_check(check, elem)
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks')
      checks.elements.delete("Disabled/#{elem}[@name='#{check}']")
      enabled_checks = checks.elements['Enabled'] || checks.add_element('Enabled')
      enabled_checks.add_element(elem, { 'name' => check })
    end

    def _disable_check(check, elem)
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks')
      checks.elements.delete("Enabled/#{elem}[@name='#{check}']")
      disabled_checks = checks.elements['Disabled'] || checks.add_element('Disabled')
      disabled_checks.add_element(elem, { 'name' => check })
    end

    def _remove_check(check, elem)
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks')
      checks.elements.delete("Disabled/#{elem}[@name='#{check}']")
      checks.elements.delete("Enabled/#{elem}[@name='#{check}']")
    end

    # Get a list of the individual vuln checks enabled for this scan template.
    #
    # @return [Array[String]] List of enabled vulnerability checks.
    #
    def enabled_vuln_checks
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks/Enabled')
      checks ? checks.elements.to_a('Check').map { |c| c.attributes['id'] } : []
    end

    # Get a list of the individual vuln checks disabled for this scan template.
    #
    # @return [Array[String]] List of enabled vulnerability checks.
    #
    def disabled_vuln_checks
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks/Disabled')
      checks ? checks.elements.to_a('Check').map { |c| c.attributes['id'] } : []
    end

    # Enable individual check for this template.
    #
    # @param [String] check_id Unique identifier of vuln check.
    #
    def enable_vuln_check(check_id)
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks')
      checks.elements.delete("Disabled/Check[@id='#{check_id}']")
      enabled_checks = checks.elements['Enabled'] || checks.add_element('Enabled')
      enabled_checks.add_element('Check', { 'id' => check_id })
    end

    # Disable individual check for this template.
    #
    # @param [String] check_id Unique identifier of vuln check.
    #
    def disable_vuln_check(check_id)
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks')
      checks.elements.delete("Enabled/Check[@id='#{check_id}']")
      disabled_checks = checks.elements['Disabled'] || checks.add_element('Disabled')
      disabled_checks.add_element('Check', { 'id' => check_id })
    end

    # Remove individual check for this template. Removes both enabled and
    # disabled checks.
    #
    # @param [String] check_id Unique identifier of vuln check.
    #
    def remove_vuln_check(check_id)
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks')
      checks.elements.delete("Disabled/Check[@id='#{check_id}']")
      checks.elements.delete("Enabled/Check[@id='#{check_id}']")
    end

    # Save this scan template configuration to a Nexpose console.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    #
    def save(nsc)
      root = REXML::XPath.first(@xml, 'ScanTemplate')
      if root.attributes['id'] == '#NewScanTemplate#'
        response = JSON.parse(AJAX.post(nsc, '/data/scan/templates', xml))
        root.attributes['id'] = response['value']
      else
        response = JSON.parse(AJAX.put(nsc, "/data/scan/templates/#{URI.encode(id)}", xml))
      end
      response['value']
    end

    # Load a scan template.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] id Unique identifier of an existing scan template.
    #   If no ID is provided, a blank, base template will be returned.
    # @return [ScanTemplate] The requested scan template configuration.
    #
    def self.load(nsc, id = nil)
      if id
        response = JSON.parse(AJAX.get(nsc, "/data/scan/templates/#{URI.encode(id)}"))
        xml = response['value']
      else
        xml = AJAX.get(nsc, '/data/scan-template')
      end
      new(xml)
    end

    # Copy an existing scan template, changing the id and title.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] id Unique identifier of an existing scan template.
    # @return [ScanTemplate] A copy of the requested scan template configuration.
    #
    def self.copy(nsc, id)
      dupe = load(nsc, id)
      dupe.id   = '#NewScanTemplate#'
      dupe.name = "#{dupe.name} Copy"
      dupe
    end

    # Delete this scan template from the console.
    # Cannot be used to delete a built-in template.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    #
    def delete(nsc)
      nsc.delete_scan_template(id)
    end

    # Enable or disable asset configuration scanning for this template. If
    # the level is not "full", "default" or "none", this is a no-op.
    #
    # @param [String] "full" to enable asset configuration logging, and
    #   "default" or "none" to disable it.
    def aces_level=(level)
      return if level.nil?
      return unless ['full', 'default', 'none'].include? level.downcase
      logging = REXML::XPath.first(@xml, 'ScanTemplate/Logging')
      if logging.nil?
        logging = REXML::Element.new('Logging')
        @xml.add_element(logging)
      end
      aces = REXML::XPath.first(logging, 'aces')
      if aces.nil?
        aces = REXML::Element.new('aces')
        logging.add_element(aces)
      end
      aces.attributes['level'] = level
    end

    # @return [String] the asset configuration logging value for this
    #   template.
    def aces_level
      logging = REXML::XPath.first(@xml, 'ScanTemplate/Logging')
      return 'default' if logging.nil?
      aces = REXML::XPath.first(logging, 'aces')
      return 'default' if aces.nil?
      aces.attributes['level']
    end

    # @return [Boolean] whether asset configuration scanning is enabled for
    #   this template.
    def aces_enabled?
      aces_level == 'full'
    end

    # Enable or disable the debug logging.
    # @param [Boolean] enable Enable or disable the debug logging.
    def enable_debug_logging=(enable)
      return if enable.nil?
      logging = REXML::XPath.first(@xml, 'ScanTemplate/Logging')
      if logging.nil?
        logging = REXML::Element.new('Logging')
        @xml.add_element(logging)
      end
      debug_logging = REXML::XPath.first(logging, 'debugLogging')
      if debug_logging.nil?
        debug_logging = REXML::Element.new('debugLogging')
        logging.add_element(debug_logging)
      end
      debug_logging.attributes['enabled'] = (enable ? 1 : 0)
    end

    # Enable or disable the enhanced logging.
    # @param [Boolean] enable Enable or disable the enhanced logging.
    def enable_enhanced_logging=(enable)
      self.enable_debug_logging = enable
      self.aces_level = (enable ? 'full' : 'none')
    end

    # Enable or disable windows service editor.
    # @param [Boolean] enable Enable or disable windows service editor.
    def windows_service_editor=(enable)
      cifs_scanner = REXML::XPath.first(@xml, 'ScanTemplate/Plugins/Plugin[@name="java/CifsScanner"]')
      param = REXML::XPath.first(cifs_scanner, './param[@name="windowsServiceEditor"]')
      if param
        param.text = (enable ? '1' : '0')
      else
        param = REXML::Element.new('param')
        param.attributes['name'] = 'windowsServiceEditor'
        param.text = (enable ? '1' : '0')
        cifs_scanner.add_element(param)
      end
      param.text
    end
  end
end
