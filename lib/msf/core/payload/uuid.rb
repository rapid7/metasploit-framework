# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/module/platform'
require 'rex/text'

#
# This class provides methods for calculating, extracting, and parsing
# unique ID values used by payloads.
#
class Msf::Payload::UUID


  #
  # Constants
  #

  Architectures = {
     0 => nil,
     1 => ARCH_X86,
     2 => ARCH_X64, # removed ARCH_X86_64, now consistent across the board
     3 => ARCH_X64,
     4 => ARCH_MIPS,
     5 => ARCH_MIPSLE,
     6 => ARCH_MIPSBE,
     7 => ARCH_PPC,
     8 => ARCH_PPC64,
     9 => ARCH_CBEA,
    10 => ARCH_CBEA64,
    11 => ARCH_SPARC,
    12 => ARCH_ARMLE,
    13 => ARCH_ARMBE,
    14 => ARCH_CMD,
    15 => ARCH_PHP,
    16 => ARCH_TTY,
    17 => ARCH_JAVA,
    18 => ARCH_RUBY,
    19 => ARCH_DALVIK,
    20 => ARCH_PYTHON,
    21 => ARCH_NODEJS,
    22 => ARCH_FIREFOX,
    23 => ARCH_ZARCH,
    24 => ARCH_AARCH64,
    25 => ARCH_MIPS64,
    26 => ARCH_PPC64LE,
    27 => ARCH_R,
    28 => ARCH_PPCE500V2
  }

  Platforms = {
     0 => nil,
     1 => 'windows',
     2 => 'netware',
     3 => 'android',
     4 => 'java',
     5 => 'ruby',
     6 => 'linux',
     7 => 'cisco',
     8 => 'solaris',
     9 => 'osx',
    10 => 'bsd',
    11 => 'openbsd',
    12 => 'bsdi',
    13 => 'netbsd',
    14 => 'freebsd',
    15 => 'aix',
    16 => 'hpux',
    17 => 'irix',
    18 => 'unix',
    19 => 'php',
    20 => 'js',
    21 => 'python',
    22 => 'nodejs',
    23 => 'firefox',
    24 => 'r',
    25 => 'apple_ios',
    26 => 'juniper',
    27 => 'unifi',
    28 => 'brocade',
  }

  # The raw length of the UUID structure
  RawLength = 16

  # The base64url-encoded length of the UUID structure
  UriLength = 22

  # Validity constraints for UUID timestamps in UTC
  TimestampMaxFuture = Time.now.utc.to_i + (30*24*3600) # Up to 30 days in the future
  TimestampMaxPast   = 1420070400                       # Since 2015-01-01 00:00:00 UTC

  #
  # Class Methods
  #

  #
  # Generate a raw 16-byte payload UUID given a seed, platform, architecture, and timestamp
  #
  # @option opts [String] :seed An optional string to use for generated the unique payload ID, deterministic
  # @option opts [String] :puid An optional 8-byte string to use as the unique payload ID
  # @option opts [String] :arch The hardware architecture for this payload
  # @option opts [String] :platform The operating system platform for this payload
  # @option opts [String] :timestamp The timestamp in UTC Unix epoch format
  # @option opts [Integer] :xor1 An optional 8-bit XOR ID for obfuscation
  # @option opts [Integer] :xor2 An optional 8-bit XOR ID for obfuscation
  # @return [String] The encoded payoad UUID as a binary string
  #
  def self.generate_raw(opts={})
    plat_id = find_platform_id(opts[:platform]) || 0
    arch_id = find_architecture_id(opts[:arch]) || 0
    tstamp  = opts[:timestamp] || Time.now.utc.to_i
    puid    = opts[:puid]

    if opts[:seed]
      puid = seed_to_puid(opts[:seed])
    end

    puid ||= SecureRandom.random_bytes(8)

    if puid.length != 8
      raise ArgumentError, "The :puid parameter must be exactly 8 bytes"
    end

    plat_xor = opts[:xor1] || rand(256)
    arch_xor = opts[:xor2] || rand(256)

    # Recycle the previous two XOR bytes to keep our output small
    time_xor = [plat_xor, arch_xor, plat_xor, arch_xor].pack('C4').unpack('N').first

    # Combine the payload UID with the arch/platform and use xor to
    # obscure the platform, architecture, and timestamp
    puid +
      [
        plat_xor, arch_xor,
        plat_xor ^ plat_id,
        arch_xor ^ arch_id,
        time_xor ^ tstamp
      ].pack('C4N')
  end

  #
  # Parse a raw 16-byte payload UUID and return the payload ID, platform, architecture, and timestamp
  #
  # @param raw [String] The raw 16-byte payload UUID to parse
  # @return [Hash] A hash containing the Payload ID, platform, architecture, and timestamp
  #
  def self.parse_raw(raw)
    if raw.to_s.length < 16
      raise ArgumentError, "Raw UUID must be at least 16 bytes"
    end

    puid, plat_xor, arch_xor, plat_id, arch_id, tstamp = raw.unpack('a8C4N')
    plat     = find_platform_name(plat_xor ^ plat_id)
    arch     = find_architecture_name(arch_xor ^ arch_id)
    time_xor = [plat_xor, arch_xor, plat_xor, arch_xor].pack('C4').unpack('N').first
    time     = time_xor ^ tstamp
    { puid: puid, platform: plat, arch: arch, timestamp: time, xor1: plat_xor, xor2: arch_xor }
  end

  #
  # Generate a 8-byte payload ID given a seed string
  #
  # @param seed [String] The seed to use to calculate a deterministic payload ID
  # @return [String] The 8-byte payload ID
  #
  def self.seed_to_puid(seed)
    Rex::Text.sha1_raw(seed)[12,8]
  end

  #
  # Filter out UUIDs with obviously invalid fields and return either
  # a validated UUID or a UUID with the arch, platform, and timestamp
  # fields strippped out.
  #
  # @param uuid [Hash] The UUID in hash format
  # @return [Hash] The filtered UUID in hash format
  #
  def self.filter_invalid(uuid)
    # Verify the UUID fields and return just the Payload ID unless the
    # timestamp is within our constraints and the UUID has either a
    # valid architecture or platform
    if uuid[:timestamp] > TimestampMaxFuture ||
       uuid[:timestamp] < TimestampMaxPast   ||
       (uuid[:arch].nil? && uuid[:platform].nil?)
       return { puid: uuid[:puid] }
    end
    uuid
  end

  #
  # Parse a 22-byte base64url-encoded payload UUID and return the hash
  #
  # @param uri [String] The 22-byte base64url-encoded payload UUID to parse
  # @return [Hash] A hash containing the Payload ID, platform, architecture, and timestamp
  #
  def self.parse_uri(uri)
    parse_raw(Rex::Text.decode_base64url(uri))
  end


  #
  # Look up the numeric platform ID given a string or PlatformList as input
  #
  # @param platform [String] The name of the platform to lookup
  # @return [Integer] The integer value of this platform
  #
  def self.find_platform_id(platform)
    # Handle a PlatformList input by grabbing the first entry
    if platform.respond_to?(:platforms)
      platform = platform.platforms.first.realname.downcase
    end

    # Map a platform abbreviation to the real name
    name = platform ? Msf::Platform.find_platform(platform) : nil
    if name && name.respond_to?(:realname)
      name = name.realname.downcase
    end

    ( Platforms.keys.select{ |k|
      Platforms[k] == name
    }.first || Platforms[0] ).to_i
  end

  #
  # Look up the numeric architecture ID given a string as input
  #
  # @param name [String] The name of the architecture to lookup
  # @return [Integer] The integer value of this architecture
  #
  def self.find_architecture_id(name)
    name = name.first if name.kind_of? ::Array
    ( Architectures.keys.select{ |k|
      Architectures[k] == name
    }.first || Architectures[0] ).to_i
  end

  def self.find_platform_name(num)
    Platforms[num]
  end

  def self.find_architecture_name(num)
    Architectures[num]
  end

  #
  # Instance methods
  #

  def initialize(opts=nil)
    opts = load_new if opts.nil?
    opts = load_uri(opts[:uri]) if opts[:uri]
    opts = load_raw(opts[:raw]) if opts[:raw]

    self.puid      = opts[:puid]
    self.timestamp = opts[:timestamp]
    self.arch      = opts[:arch]
    self.platform  = opts[:platform]
    self.xor1      = opts[:xor1]
    self.xor2      = opts[:xor2]

    self.timestamp  = nil
    self.name       = nil
    self.registered = false

    if opts[:seed]
      self.puid = self.class.seed_to_puid(opts[:seed])
    end

    # Generate some sensible defaults
    self.puid ||= SecureRandom.random_bytes(8)
    self.xor1 ||= rand(256)
    self.xor2 ||= rand(256)
    self.timestamp ||= Time.now.utc.to_i
  end

  #
  # Initializes a UUID object given a raw 16+ byte blob
  #
  # @param raw [String] The string containing at least 16 bytes of encoded data
  # @return [Hash] The attributes encoded into this UUID
  #
  def load_raw(raw)
    self.class.filter_invalid(self.class.parse_raw(raw))
  end

  #
  # Initializes a UUID object given a 22+ byte URI
  #
  # @param uri [String] The URI containing at least 22 bytes of encoded data
  # @return [Hash] The attributes encoded into this UUID
  #
  def load_uri(uri)
    self.class.filter_invalid(self.class.parse_uri(uri))
  end

  def load_new
   self.class.parse_raw(self.class.generate_raw())
  end

  #
  # Provides a string representation of a UUID
  #
  # @return [String] The human-readable version of the UUID data
  #
  def to_s
    arch_id   = self.class.find_architecture_id(self.arch).to_s
    plat_id   = self.class.find_platform_id(self.platform).to_s
    [
      self.puid_hex,
      [ self.arch     || "noarch",     arch_id ].join("="),
      [ self.platform || "noplatform", plat_id ].join("="),
      Time.at(self.timestamp.to_i).utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    ].join("/")
  end

  #
  # Return a string that represents the Meterpreter arch/platform
  #
  def session_type
    # mini-patch for x86 so that it renders x64 instead. This is
    # mostly to keep various external modules happy.
    arch = self.arch
    if arch == ARCH_X86_64
        arch = ARCH_X64
    end
    "#{arch}/#{self.platform}"
  end

  #
  # Provides a hash representation of a UUID
  #
  # @return [Hash] The hash representation of the UUID suitable for creating a new one
  #
  def to_h
    {
        puid: self.puid,
        arch: self.arch, platform: self.platform,
        timestamp: self.timestamp,
        xor1: self.xor1, xor2: self.xor2
    }
  end

  #
  # Provides a raw byte representation of a UUID
  #
  # @return [String] The 16-byte raw encoded version of the UUID
  #
  def to_raw
    self.class.generate_raw(self.to_h)
  end

  #
  # Provides a URI-encoded representation of a UUID
  #
  # @return [String] The 22-byte URI encoded version of the UUID
  #
  def to_uri
    Rex::Text.encode_base64url(self.to_raw)
  end

  #
  # Provides a hex representation of the Payload UID of the UUID
  #
  # @return [String] The 16-byte hex string representing the Payload UID
  #
  def puid_hex
    self.puid.unpack('H*').first
  end

  #
  # Clears the two random XOR keys used for obfuscation
  #
  def xor_reset
    self.xor1 = self.xor2 = nil
    self
  end

  attr_accessor :registered
  attr_accessor :timestamp
  attr_accessor :name

  attr_reader :arch
  attr_reader :platform

  def arch=(arch_str)
    if arch_str.nil?
      @arch = nil
      return
    end

    arch_id   = self.class.find_architecture_id(arch_str)
    if arch_id == 0
      raise ArgumentError, "Invalid architecture: '#{arch_str}'"
    end

    arch_name = self.class.find_architecture_name(arch_id)
    @arch = arch_name
  end

  def platform=(plat_str)
    if plat_str.nil?
      @platform = nil
      return
    end

    plat_id = self.class.find_platform_id(plat_str)
    if plat_id == 0
      raise ArgumentError, "Invalid platform: '#{plat_str}'"
    end

    plat_name = self.class.find_platform_name(plat_id)
    @platform = plat_name
  end

  attr_accessor :timestamp
  attr_accessor :puid
  attr_accessor :xor1
  attr_accessor :xor2
end
