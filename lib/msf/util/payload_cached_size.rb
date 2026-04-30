# -*- coding: binary -*-
###
#
#
###

module Msf
module Util

#
# The class provides helper methods for verifying and updating the embedded CachedSize
# constant within payload modules.
#

class PayloadCachedSize

  OPTS = {
    'Format'      => 'raw',
    'Options'     => {
      'VERBOSE' => false,
      'CPORT' => 4444,
      'LPORT' => 4444,
      'RPORT' => 4444,
      'CMD' => '/bin/sh',
      'URL' => 'http://a.com',
      'PATH' => '/',
      'BUNDLE' => 'data/isight.bundle',
      'DLL' => 'external/source/byakugan/bin/XPSP2/detoured.dll',
      'RC4PASSWORD' => 'Metasploit',
      'DNSZONE' => 'corelan.eu',
      'PEXEC' => '/bin/sh',
      'HttpUserAgent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0',
      'StagerURILength' => 5,
      'FD' => 100,
      'MeterpreterDebugBuild' => false
    },
    'Encoder'     => nil,
    'DisableNops' => true
  }

  OPTS_ARCH_X64 = {
    'DLL' => 'data/vncdll.x64.dll',
    'PE' => 'data/vncdll.x64.dll'
  }.freeze

  OPTS_ARCH_X86 = {
    'DLL' => 'data/vncdll.x86.dll',
    'PE' => 'data/vncdll.x86.dll'
  }.freeze

  OPTS_IPV4 = {
    'LHOST' => '223.255.255.255',
    'RHOST' => '255.255.255.255',
    'KHOST' => '255.255.255.255',
    'AHOST' => '255.255.255.255'
  }.freeze

  OPTS_IPV6 = {
    'LHOST' => 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'RHOST' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'KHOST' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'AHOST' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
  }.freeze

  # Inserts or updates the CachedSize constant in the text of a payload module.
  #
  # @param data [String] The source code of a payload module
  # @param cached_size [String, Integer] The new value for CachedSize, which should be either an integer or the string ":dynamic"
  # @return [String] The updated source code with the new CachedSize value
  def self.update_cache_constant(data, cached_size)
    data.
      gsub(/^\s*CachedSize\s*=\s*(\d+|:dynamic).*/, '').
      gsub(/^(module MetasploitModule)\s*\n/) do |m|
        "#{m.strip}\n  CachedSize = #{cached_size}\n\n"
      end
  end

  # Inserts or updates the CachedSizeOverrides constant in the text of a payload module,
  # removing any previous CachedSizeStages, # Other stager sizes, or CachedSizeOverrides lines.
  #
  # @param data [String] The source code of a payload module
  # @param stages_with_sizes [Array<{:stage => Msf::Payload::Stager, :size => Integer}>] Array of hashes with :stage (an Msf::Payload::Stager instance) and :size (Integer)
  # @return [String] The updated source code with the new CachedSizeOverrides value
  def self.update_stage_sizes_constant(data, stages_with_sizes)
    sizes = stages_with_sizes.sort_by { |stage_with_size| stage_with_size[:stage].refname }.map do |stage_with_size|
      [stage_with_size[:stage].refname, stage_with_size[:size]]
    end
      data_without_other_stages = data.gsub(/^\s*CachedSizeOverrides\s*=.*\n/, '')
    return data_without_other_stages if sizes.empty?

    data_without_other_stages.gsub(/^\s*(CachedSize\s*=\s*(\d+|:dynamic))\s*\n/) do |m|
      "  #{m.strip}\n  CachedSizeOverrides = {#{sizes.map { |(k, v)| %Q{"#{k}" => #{v}}}.join(', ')}}\n\n"
    end
  end

  # Insert or update the CachedSize value into a payload module file
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @param cached_size [String, Integer] The new value for cached_size, which
  #   should be either an integer or the string ":dynamic"
  # @return [void]
  def self.update_cached_size(mod, cached_size)
    mod_data = ""

    file_path = mod.file_path

    ::File.open(file_path, 'rb') do |fd|
      mod_data = fd.read(fd.stat.size)
    end

    ::File.open(file_path, 'wb') do |fd|
      fd.write update_cache_constant(mod_data, cached_size)
    end
  end

  # Insert or update the CachedSize value into a payload module file
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @param stages_with_sizes [Array<{:stage => Msf::Payload::Stager, :size => Integer}>] Array of hashes with :stage (an Msf::Payload::Stager instance) and :size (Integer)
  # @return [void]
  def self.update_stager_cached_sizes(mod, stages_with_sizes)
    mod_data = ""

    file_path = mod.file_path

    ::File.open(file_path, 'rb') do |fd|
      mod_data = fd.read(fd.stat.size)
    end

    ::File.open(file_path, 'wb') do |fd|
      fd.write update_stage_sizes_constant( mod_data, stages_with_sizes)
    end
  end

  # Updates the payload module specified with the current CachedSize
  #
  # @param framework [Msf::Framework] The Metasploit framework instance used for payload generation
  # @param mod [Msf::Payload] The class of the payload module to update
  # @return [String, Integer] The updated CachedSize value
  def self.update_module_cached_size(framework, mod)
    cached_size = compute_cached_size(framework, mod)
    update_cached_size(mod, cached_size)
    cached_size
  end

  # Updates the stager payload module with the most frequent CachedSize value and sets CachedSizeOverrides for other stages.
  #
  # @param framework [Msf::Framework] The Metasploit framework instance used for payload generation
  # @param stages [Array<Msf::Payload>] Array of stager modules to update
  # @return [Integer, String] The new CachedSize value set for the stager
  def self.update_stager_module_cached_size(framework, stages)
    stages_with_sizes = stages.map do |stage|
      { stage: stage, size: compute_cached_size(framework, stage) }
    end
    most_frequent_cached_size = stages_with_sizes.map { |stage_with_size| stage_with_size[:size] }
                            .select { |size| size.is_a?(Numeric) }.tally.sort_by(&:last).to_h.keys.last

    new_size = most_frequent_cached_size || stages_with_sizes.first[:size]
    other_sizes = stages_with_sizes.select { |stage_with_size| stage_with_size[:size] != new_size }

    update_cached_size(stages.first, new_size)
    update_stager_cached_sizes(stages.first, other_sizes)

    new_size
  end

  # Calculates the CachedSize value for a payload module
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @return [Integer, String]
  def self.compute_cached_size(framework, mod)
    return ":dynamic" if is_dynamic?(framework, mod)

    mod.replicant.generate_simple(module_options(mod)).bytesize
  end

  # Determines whether a payload generates a static sized output
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @param generation_count [Integer] The number of iterations to use to
  #   verify that the size is static.
  # @return [Boolean]
  def self.is_dynamic?(framework, mod, generation_count=10)
    return true if mod.class.const_defined?('ForceDynamicCachedSize') && mod.class::ForceDynamicCachedSize
    opts = module_options(mod)
    last_bytesize = nil
    generation_count.times do
      # Ensure a new module instance is created for each attempt, as some options are randomized on load - such as tmp file path names etc
      new_mod = framework.payloads.create(mod.refname)
      bytesize = new_mod.generate_simple(opts).bytesize
      last_bytesize ||= bytesize
      if last_bytesize != bytesize
        return true
      end
    end

    false
  end

  # Determines whether a payload's CachedSize is up to date
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @return [Boolean]
  def self.is_cached_size_accurate?(framework, mod)
    return true if mod.dynamic_size? && is_dynamic?(framework, mod)
    return false if mod.cached_size.nil?

    mod.cached_size == mod.replicant.generate_simple(module_options(mod)).bytesize
  end

  # Checks for errors or inconsistencies in the CachedSize value for a payload module.
  # Returns nil if the cache is correct, or a string describing the error if not.
  #
  # @param framework [Msf::Framework] The Metasploit framework instance used for payload generation
  # @param mod [Msf::Payload] The payload module to check
  # @return [String, nil] Error message if there is a problem, or nil if the cache is correct
  def self.cache_size_errors_for(framework, mod)
    is_payload_size_different_on_each_generation = is_dynamic?(framework,mod)
    module_marked_as_dynamic = mod.dynamic_size?
    payload_cached_static_size = mod.cached_size

    # Validate dynamic scenario
    return if is_payload_size_different_on_each_generation && module_marked_as_dynamic

    if is_payload_size_different_on_each_generation && !module_marked_as_dynamic
      return 'Module generated different sizes for each generation attempt. CacheSize must be set to :dynamic'
    end

    if payload_cached_static_size.nil?
      return 'Module missing CachedSize and not marked as dynamic'
    end

    payload_size_after_one_generation = mod.replicant.generate_simple(module_options(mod)).bytesize

    # Validate static scenario
    return if payload_cached_static_size == payload_size_after_one_generation

    if payload_cached_static_size != payload_size_after_one_generation
      return "Module marked as having size #{payload_cached_static_size} but after one generation was #{payload_size_after_one_generation}"
    end

    raise "unhandled scenario"
  end

  # Get a set of sane default options for the module so it can generate a
  # payload for size analysis.
  #
  # @param mod [Msf::Payload] The class of the payload module to get options for
  # @return [Hash]
  def self.module_options(mod)
    opts = OPTS.clone
    # Assign this way to overwrite the Options key of the newly cloned hash
    opts['Options'] = opts['Options'].merge(mod.shortname =~ /6/ ? OPTS_IPV6 : OPTS_IPV4)
    # Extract the AdaptedArch for adaptor payloads, note `mod.adapted_arch` is not part of the public API
    # at this time, but could be in the future. The use of send is safe for now as it is an internal tool
    # with automated tests if the API were to change in the future
    adapted_arch = mod.send(:module_info)['AdaptedArch']
    if adapted_arch == ARCH_X64 || mod.arch_to_s == ARCH_X64
      opts['Options'].merge!(OPTS_ARCH_X64)
    elsif adapted_arch == ARCH_X86 || mod.arch_to_s == ARCH_X86
      opts['Options'].merge!(OPTS_ARCH_X86)
    end
    opts
  end
end

end
end
