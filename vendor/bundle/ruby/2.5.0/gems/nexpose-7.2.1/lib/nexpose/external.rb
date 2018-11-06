module Nexpose
  class Connection
    # Import external assets into a Nexpose console.
    #
    # This method will synchronously import a collection of assets into the
    # console. Each call to this method will be treated as a single event.
    #
    # This method should only be used against "static" sites, i.e., those not
    # tied to a dynamic population service like vSphere, AWS, etc.
    #
    # If a paused scan exists on the site at the time of import, the newly
    # imported assets will not be included in the scan when it resumes.
    #
    # @param [Fixnum] site_id Existing site to import assets into.
    # @param [Array[External::Asset]] assets External assets to import.
    # @return [Array[ImportResult]] collection of import results.
    #
    def import_assets(site_id, assets)
      json = JSON.generate(Array(assets).map(&:to_h))
      import_assets_from_json(site_id, json)
    end

    # Import external assets into a Nexpose console.
    #
    # @param [Fixnum] site_id Existing site to import assets into.
    # @param [String] json JSON representation of assets to import.
    # @return [Array[ImportResult]] collection of import results.
    #
    def import_assets_from_json(site_id, json)
      uri  = "/api/2.1/sites/#{site_id}/assets"
      # Wait up to 5 minutes for a response.
      resp = AJAX.post(self, uri, json, AJAX::CONTENT_TYPE::JSON, 300)
      arr  = JSON.parse(resp, symbolize_names: true)
      arr.map { |e| External::ImportResult.new.object_from_hash(self, e) }
    end
  end

  # Namespace for functionality around importing external assets into Nexpose.
  #
  module External
    # Object for importing assets from external sources into a Nexpose console.
    # This exists primarily as a convenience for marshalling the data into the
    # proper JSON format.
    #
    # In order to successfully import an asset, it must contain at least one
    # scannable identifier: IP address, fully qualified domain name, or NetBIOS
    # name. This ensures that once an asset is imported to the console, it can
    # be scanned.
    #
    # Besides a scannable identifier, all other fields are optional.
    #
    class Asset
      # IPv4 or IPv6 that is the primary identifier of the asset.
      attr_accessor :ip
      # A fully qualified domain name of the asset.
      attr_accessor :fqdn
      # A NetBIOS name of the asset.
      attr_accessor :net_bios
      # The MAC address of the asset.
      attr_accessor :mac
      # The host type of the asset. One of: GUEST, HYPERVISOR, PHYSICAL, MOBILE.
      attr_accessor :host_type
      # A list of alternate identifiers of the asset. This can include additional
      # IP addresses and host names.
      attr_accessor :aliases
      # The date the asset was scanned. If left blank, the current time will be
      # used by the console. Use the ISO 8601 basic date-time format.
      # For example: 20141211T100614.526Z
      attr_accessor :scan_date
      # The CPE for the operating system on the asset.
      attr_accessor :os
      # A list of CPEs identifying software installed on the asset.
      attr_accessor :software
      # A list of service endpoints on the asset.
      attr_accessor :services
      # A list of user accounts on the asset.
      attr_accessor :users
      # A list of group accounts on the asset.
      attr_accessor :groups
      # Files and directories on the asset.
      attr_accessor :files
      # Unique system identifiers on the asset.
      attr_accessor :unique_identifiers
      # A list of key-value attributes associated with the asset.
      attr_accessor :attributes
      # Asset-level vulnerabilities.
      attr_accessor :vulnerabilities

      def initialize
        @aliases            = []
        @software           = []
        @services           = []
        @attributes         = []
        @users              = []
        @groups             = []
        @files              = []
        @unique_identifiers = []
        @vulnerabilities    = []
      end

      def to_json
        JSON.generate(to_h)
      end

      def to_h
        { ip: ip,
          fqdn: fqdn,
          net_bios: net_bios,
          mac: mac,
          host_type: host_type,
          aliases: aliases,
          scan_date: scan_date,
          os: os,
          software: software,
          services: services.map(&:to_h),
          users: users.map(&:to_h),
          groups: groups.map(&:to_h),
          files: files.map(&:to_h),
          unique_identifiers: unique_identifiers.map(&:to_h),
          vulnerabilities: vulnerabilities.map(&:to_h),
          attributes: Attributes.to_hash(attributes) }
      end

      # Valid host types for an asset.
      module HostType
        GUEST      = 'GUEST'
        HYPERVISOR = 'HYPERVISOR'
        PHYSICAL   = 'PHYSICAL'
        MOBILE     = 'MOBILE'
      end
    end

    # A service endpoint on an asset.
    #
    class Service
      # Name of the service. [Optional]
      attr_accessor :name
      # Port on which the service is running.
      attr_accessor :port
      # Protocol used to communicate to the port. @see Service::Protocol.
      attr_accessor :protocol
      # Vulnerabilities specific to this service endpoint.
      attr_accessor :vulnerabilities

      def initialize(port, protocol = Protocol::RAW, name = nil)
        @port            = port
        @protocol        = protocol
        @name            = name
        @vulnerabilities = []
      end

      def to_h
        { name: name,
          port: port,
          protocol: protocol,
          vulnerabilities: vulnerabilities.map(&:to_h) }
      end
    end

    # Vulnerability check object for importing vulnerabilities into Nexpose.
    #
    class VulnerabilityCheck
      # Unique identifier of a vulnerability in Nexpose.
      attr_accessor :vuln_id
      # Status of the vulnerability. @see VulnerabilityCheck::Status
      attr_accessor :status
      # Unique identifier of a vulnerability instance, typically used for spider
      # vulns or when multiple instances of a vuln exist on the same service.
      attr_accessor :key
      # Explanation of what proves that an asset or service is vulnerable.
      attr_accessor :proof

      def initialize(vuln_id, status = Status::EXPLOITED, proof = nil, key = nil)
        @vuln_id = vuln_id
        @status  = status
        @proof   = proof
        @key     = key
      end

      def to_h
        { vuln_id: vuln_id,
          status: status,
          key: key,
          proof: proof }
      end

      # Valid vulnerability status for import into Nexpose.
      module Status
        # Vulnerability verified by exploit.
        EXPLOITED = 'vulnerable-exploited'
        # Vulnerable because the service or software version is associated with
        # a known vulnerability.
        VERSION   = 'vulnerable-version'
        # A potential vulnerability.
        POTENTIAL = 'potential'
      end
    end

    # Result object returned from an import_assets call, used to correlate the
    # supplied scannable identifier with the resulting asset ID or any error
    # messages from a problematic import.
    #
    class ImportResult < APIObject
      # IP or hostname provided during import.
      attr_reader :name
      # Resulting asset ID of the created asset, if any.
      attr_reader :asset_id
      # The asset created by the import. [Lazy]
      attr_reader :asset
      # Any error messages associated with the import of the asset.
      attr_reader :error_message
    end
  end
end
