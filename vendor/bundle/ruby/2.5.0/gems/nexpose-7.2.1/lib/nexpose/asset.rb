module Nexpose
  # Asset object as return from the 2.1 API.
  #
  class Asset < APIObject
    # Unique identifier of the asset on the Nexpose console.
    attr_reader :id
    # Primary IP address of the asset.
    attr_reader :ip
    # MAC address of the asset.
    attr_reader :mac
    # Known host names found for the asset.
    attr_reader :host_names
    # Operating system name.
    attr_reader :os_name
    # The CPE for the asset's operating system.
    attr_reader :os_cpe
    # The host type of the asset. One of: GUEST, HYPERVISOR, PHYSICAL, MOBILE.
    attr_reader :host_type

    # Assessment summary of the asset, including most recent scan info. [Lazy]
    attr_reader :assessment
    # Service endpoints enumerated on the asset. [Lazy]
    attr_reader :services
    # Software enumerated on the asset. [Lazy]
    attr_reader :software
    # Vulnerabilities detected on the asset. [Lazy]
    attr_reader :vulnerabilities
    # Vulnerability instances detected on the asset. [Lazy]
    attr_reader :vulnerability_instances
    # Vulnerability exploits to which this asset is susceptible. [Lazy]
    attr_reader :exploits
    # Malware kits to which this asset is susceptible. [Lazy]
    attr_reader :malware_kits

    # User accounts enumerated on the asset. [Lazy]
    attr_reader :user_accounts
    # Group accounts enumerated on the asset. [Lazy]
    attr_reader :group_accounts
    # Files and directories that have been enumerated on the asset. [Lazy]
    attr_reader :files
    # Unique system identifiers on the asset.
    attr_accessor :unique_identifiers

    def initialize
      @addresses  = []
      @host_names = []
    end

    # Load an asset from the provided console.
    #
    # @param [Connection] nsc Active connection to a Nexpose console.
    # @param [Fixnum] id Unique identifier of an asset.
    # @return [Asset] The requested asset, if found.
    #
    def self.load(nsc, id)
      uri  = "/api/2.1/assets/#{id}"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true)
      new.object_from_hash(nsc, hash)
    end
  end

  # Software found on an asset.
  #
  class Software < APIObject
    # The software product name.
    attr_reader :product
    # The version of software detected.
    attr_reader :version
    # Name of the vendor publishing the software.
    attr_reader :vendor
    # The family of software.
    attr_reader :family
    # Type of software.
    attr_reader :type
  end

  # A service endpoint on an asset.
  #
  class Service < APIObject
    # Name of the service. [Optional]
    attr_reader :name
    # Port on which the service is running.
    attr_reader :port
    # Protocol used to communicate to the port. @see Service::Protocol.
    attr_reader :protocol

    def initialize(port = 0, protocol = Protocol::RAW, name = nil)
      @port, @protocol, @name = port, protocol, name
    end

    def to_h
      { name: name,
        port: port,
        protocol: protocol }
    end

    def <=>(other)
      c = port <=> other.port
      return c unless c.zero?
      c = protocol <=> other.protocol
      return c unless c.zero?
      name <=> other.name
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      port.eql?(other.port) && protocol.eql?(other.protocol) && name.eql?(other.name)
    end

    # Valid protocol values for a service endpoint.
    module Protocol
      # Internet Protocol
      IP   = 'IP'
      # Internet Control Message Protocol
      ICMP = 'ICMP'
      # Internet Group Management Protocol
      IGMP = 'IGMP'
      # Gateway-to-Gateway Protocol
      GGP  = 'GGP'
      # Transmission Control Protocol
      TCP  = 'TCP'
      # PARC Universal Protocol
      PUP  = 'PUP'
      # User Datagram Protocol
      UDP  = 'UDP'
      # Internet Datagram Protocol
      IDP  = 'IDP'
      # Encapsulating Security Payload
      ESP  = 'ESP'
      # Network Disk Protocol
      ND   = 'ND'
      # Raw Packet (or unknown)
      RAW  = 'RAW'
    end
  end

  # User accounts on an asset.
  #
  class UserAccount < APIObject
    # User account name.
    attr_reader :name
    # Unique identifier of the user as determined by the asset (not Nexpose).
    attr_reader :id
    # Full name of the user.
    attr_reader :full_name
    # Account attributes.
    attr_reader :attributes

    def initialize(name = nil, id = 0, full_name = nil, attributes = [])
      @id, @name, @full_name, @attributes = id, name, full_name, attributes
    end

    def to_h
      { name: name,
        id: id,
        full_name: full_name,
        attributes: Attributes.to_hash(attributes) }
    end

    def <=>(other)
      c = name <=> other.name
      return c unless c.zero?
      c = id <=> other.id
      return c unless c.zero?
      c = full_name <=> other.full_name
      return c unless c.zero?
      attributes <=> other.attributes
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      name.eql?(other.name) && id.eql?(other.id) && full_name.eql?(other.full_name) && attributes.eql?(other.attributes)
    end
  end

  # Group accounts on an asset.
  #
  class GroupAccount < APIObject
    # Group account name.
    attr_reader :name
    # Unique identifier of the group as determined by the asset (not Nexpose).
    attr_reader :id
    # Group attributes.
    attr_reader :attributes

    def initialize(name = nil, id = 0, attributes = [])
      @name = name
      @id = id
      @attributes = attributes
    end

    def to_h
      { name: name,
        id: id,
        attributes: Attributes.to_hash(attributes) }
    end

    def <=>(other)
      c = name <=> other.name
      return c unless c.zero?
      c = id <=> other.id
      return c unless c.zero?
      attributes <=> other.attributes
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      name.eql?(other.name) && id.eql?(other.id) && attributes.eql?(other.attributes)
    end
  end

  # File or directory on an asset.
  #
  class File < APIObject
    # Name of the file.
    attr_reader :name
    # Size of the file.
    attr_reader :size
    # File attributes.
    attr_reader :attributes
    # Whether the file is a directory.
    attr_reader :directory

    def initialize(name = nil, size = 0, directory = false, attributes = [])
      @name, @size, @directory, @attributes = name, size, directory, attributes
    end

    def directory?
      directory
    end

    def to_h
      { name: name,
        size: size,
        directory: directory,
        attributes: Attributes.to_hash(attributes) }
    end

    def <=>(other)
      c = name <=> other.name
      return c unless c.zero?
      c = size <=> other.size
      return c unless c.zero?
      c = directory <=> other.directory
      return c unless c.zero?
      attributes <=> other.attributes
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      name.eql?(other.name) && size.eql?(other.size) && directory.eql?(other.directory) && attributes.eql?(other.attributes)
    end
  end

  # Unique system identifiers on an asset.
  #
  class UniqueIdentifier < APIObject
    # The source name for the uniuqe identifier.
    attr_reader :source
    # Unique identifier of the user as determined by the asset (not Nexpose).
    attr_reader :id

    def initialize(source = nil, id = nil)
      @id     = id
      @source = source
    end

    def to_h
      { source: source,
        id: id }
    end

    def <=>(other)
      c = source <=> other.source
      return c unless c.zero?
      id <=> other.id
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      source.eql?(other.source) && id.eql?(other.id)
    end
  end

  # Assessment statistics for an asset.
  #
  class Assessment < APIObject
    # The date an asset was last scanned.
    attr_reader :last_scan_date
    # The ID of the scan which last assessed the asset.
    attr_reader :last_scan_id
    # The current risk score of the asset.
    attr_reader :risk_score
  end
end
