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
      'CPORT' => 4444,
      'LPORT' => 4444,
      'CMD' => '/bin/sh',
      'URL' => 'http://a.com',
      'PATH' => '/',
      'BUNDLE' => 'data/isight.bundle',
      'DLL' => 'data/vncdll.x64.dll',
      'RC4PASSWORD' => 'Metasploit',
      'DNSZONE' => 'corelan.eu',
      'PEXEC' => '/bin/sh',
      'StagerURILength' => 5
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
    'LHOST' => '255.255.255.255',
    'KHOST' => '255.255.255.255',
    'AHOST' => '255.255.255.255'
  }.freeze

  OPTS_IPV6 = {
    'LHOST' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'KHOST' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'AHOST' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
  }.freeze

  OPTS_LARGE = {
    'Format'      => 'raw',
    'Options'     => {
      'CPORT' => 55555,
      'LPORT' => 55555,
      'CMD' => '/bin/bash',
      'URL' => 'http://a_very_long_url.com',
      'PATH' => '/a/very/long/path',
      'BUNDLE' => 'data/../data/isight.bundle',
      'DLL' => 'data/../data/../data/vncdll.x64.dll',
      'RC4PASSWORD' => 'a_large_password',
      'DNSZONE' => 'a_large_dns_zone.eu',
      'PEXEC' => '/bin/bash',
      'StagerURILength' => 5
    },
    'Encoder'     => nil,
    'DisableNops' => true
  }

  OPTS_ARCH_X64_LARGE = {
    'DLL' => 'data/../data/../data/vncdll.x64.dll',
    'PE' => 'data/../data/../data/vncdll.x64.dll'
  }.freeze

  OPTS_ARCH_X86_LARGE = {
    'DLL' => 'data/../data/../data/vncdll.x86.dll',
    'PE' => 'data/../data/../data/vncdll.x86.dll'
  }.freeze

  # Insert a new CachedSize value into the text of a payload module
  #
  # @param data [String] The source code of a payload module
  # @param cached_size [String] The new value for cached_size, which
  #   which should be either numeric or the string :dynamic
  # @return [String]
  def self.update_cache_constant(data, cached_size)
    data.
      gsub(/^\s*CachedSize\s*=\s*(\d+|:dynamic).*/, '').
      gsub(/^(module MetasploitModule)\s*\n/) do |m|
        "#{m.strip}\n\n  CachedSize = #{cached_size}\n\n"
      end
  end

  # Insert a new CachedSize value into a payload module file
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @param cached_size [String] The new value for cached_size, which
  #   which should be either numeric or the string :dynamic
  # @return [void]
  def self.update_cached_size(mod, cached_size)
    mod_data = ""

    ::File.open(mod.file_path, 'rb') do |fd|
      mod_data = fd.read(fd.stat.size)
    end

    ::File.open(mod.file_path, 'wb') do |fd|
      fd.write update_cache_constant(mod_data, cached_size)
    end
  end

  # Updates the payload module specified with the current CachedSize
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @return [void]
  def self.update_module_cached_size(mod)
    update_cached_size(mod, compute_cached_size(mod))
  end

  # Calculates the CachedSize value for a payload module
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @return [Integer]
  def self.compute_cached_size(mod)
    return ":dynamic" if is_dynamic?(mod)

    mod.generate_simple(module_options(mod)).size
  end

  # Determines whether a payload generates a static sized output
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @param generation_count [Integer] The number of iterations to use to
  # verify that the size is static.
  # @return [Integer]
  def self.is_dynamic?(mod, generation_count=5)
    opts = module_options(mod)
    large_opts = module_options(mod, true)

    [*(1..generation_count)].map do |x|
      mod.generate_simple(opts).size
    end.uniq.length != 1 || (mod.generate_simple(opts).size != mod.generate_simple(large_opts).size)
  end

  # Determines whether a payload's CachedSize is up to date
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @return [Boolean]
  def self.is_cached_size_accurate?(mod)
    return true if mod.dynamic_size? && is_dynamic?(mod)
    return false if mod.cached_size.nil?

    mod.cached_size == mod.generate_simple(module_options(mod)).size
  end

  # Get a set of sane default options for the module so it can generate a
  # payload for size analysis.
  #
  # @param mod [Msf::Payload] The class of the payload module to get options for
  # @param large_opts [Boolean] Indicates if a large version of the module options should be returned.
  # Useful for testing changes in payload size with different sized modules.
  # @return [Hash]
  def self.module_options(mod, large_opts=false)
    opts = large_opts ? OPTS_LARGE.clone : OPTS.clone
    # Assign this way to overwrite the Options key of the newly cloned hash
    opts['Options'] = opts['Options'].merge(mod.shortname =~ /6/ ? OPTS_IPV6 : OPTS_IPV4)
    if mod.arch_to_s == ARCH_X64
      opts['Options'].merge!(large_opts ? OPTS_ARCH_X64_LARGE : OPTS_ARCH_X64)
    elsif mod.arch_to_s == ARCH_X86
      opts['Options'].merge!(large_opts ? OPTS_ARCH_X86_LARGE : OPTS_ARCH_X86)
    end
    opts
  end
end

end
end
