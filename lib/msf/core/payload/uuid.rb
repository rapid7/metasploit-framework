# -*- coding => binary -*-

require 'msf/core/module/platform'
require 'rex/constants'
require 'rex/text'

#
# This module provides methods for calculating, extracting, and parsing
# unique ID values used by payloads.
#
module Msf::Payload::UUID

  Architectures = {
     0 => nil,
     1 => ARCH_X86,
     2 => ARCH_X86_64,
     3 => ARCH_MIPS,
     4 => ARCH_MIPSLE,
     5 => ARCH_MIPSBE,
     6 => ARCH_PPC,
     7 => ARCH_PPC64,
     8 => ARCH_CBEA,
     9 => ARCH_CBEA64,
    10 => ARCH_SPARC,
    11 => ARCH_ARMLE,
    12 => ARCH_ARMBE,
    13 => ARCH_CMD,
    14 => ARCH_PHP,
    15 => ARCH_TTY,
    16 => ARCH_JAVA,
    17 => ARCH_RUBY,
    18 => ARCH_DALVIK,
    19 => ARCH_PYTHON,
    20 => ARCH_NODEJS,
    21 => ARCH_FIREFOX
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
    23 => 'firefox'
  }

  #
  # Generate a raw 16-byte payload UUID given a seed, platform, architecture, and timestamp
  #
  # @options opts [String] :seed A optional string to use for generated the unique payload ID, deterministic
  # @options opts [String] :arch The hardware architecture for this payload
  # @options opts [String] :platform The operating system platform for this payload
  # @options opts [String] :timestamp The timestamp in UTC Unix epoch format
  #
  def self.payload_uuid_generate_raw(opts={})
    plat_id = find_platform_id(opts[:platform]) || 0
    arch_id = find_architecture_id(opts[:arch]) || 0
    seed    = opts[:seed] || Rex::Text.rand_text(16)
    tstamp  = opts[:timestamp] || Time.now.utc.to_i

    plat_xor = rand(255)
    arch_xor = rand(255)

    # Recycle the previous two XOR bytes to keep our output small
    time_xor = [plat_xor, arch_xor, plat_xor, arch_xor].pack('C4').unpack('N').first

    # Combine the last 64-bits of the SHA1 of seed with the arch/platform
    # Use XOR to obscure the platform, architecture, and timestamp
    Rex::Text.sha1_raw(seed)[12,8] +
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
  # @return [Array] The Payload ID, platform, architecture, and timestamp
  #
  def self.payload_uuid_parse_raw(raw)
    puid, plat_xor, arch_xor, plat_id, arch_id, tstamp = raw.unpack('A8C4N')
    plat     = find_platform_name(plat_xor ^ plat_id)
    arch     = find_architecture_name(arch_xor ^ arch_id)
    time_xor = [plat_xor, arch_xor, plat_xor, arch_xor].pack('C4').unpack('N').first
    time     = time_xor ^ tstamp
    [puid, plat, arch, time]
  end

  # Alias for the class method
  def payload_uuid_generate_raw(opts)
    self.class.payload_uuid_generate_raw(opts)
  end

  # Alias for the class method
  def parse_payload_uuid_raw(raw)
    self.class.payload_uuid_parse_raw(raw)
  end

  def self.find_platform_id(platform)
    # Handle a PlatformList input by grabbing the first entry
    if platform.respond_to? :platforms
      platform = platform.platforms.first.realname.downcase
    end

    # Map a platform abbreviation to the real name
    name = Msf::Platform::Abbrev[platform]

    Platforms.keys.select{ |k|
      Platforms[k] == name
    }.first || Platforms[0]
  end

  def self.find_architecture_id(name)
    Architectures.keys.select{ |k|
      Architectures[k] == name
    }.first || Architectures[0]
  end

  def self.find_platform_name(num)
    Platforms[num]
  end

  def self.find_architecture_name(num)
    Architectures[num]
  end

end
