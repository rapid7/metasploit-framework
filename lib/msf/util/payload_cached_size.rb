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
      'LHOST' => '255.255.255.255',
      'KHOST' => '255.255.255.255',
      'AHOST' => '255.255.255.255',
      'CMD' => '/bin/sh',
      'URL' => 'http://a.com',
      'PATH' => '/',
      'BUNDLE' => 'data/isight.bundle',
      'DLL' => 'external/source/byakugan/bin/XPSP2/detoured.dll',
      'RC4PASSWORD' => 'Metasploit',
      'DNSZONE' => 'corelan.eu',
      'PEXEC' => '/bin/sh',
      'StagerURILength' => 5
    },
    'Encoder'     => nil,
    'DisableNops' => true
  }

  OPTS6 = {
    'Format'      => 'raw',
    'Options'     => {
      'CPORT' => 4444,
      'LPORT' => 4444,
      'LHOST' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
      'KHOST' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
      'AHOST' => 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
      'CMD' => '/bin/sh',
      'URL' => 'http://a.com',
      'PATH' => '/',
      'BUNDLE' => 'data/isight.bundle',
      'DLL' => 'external/source/byakugan/bin/XPSP2/detoured.dll',
      'RC4PASSWORD' => 'Metasploit',
      'DNSZONE' => 'corelan.eu',
      'PEXEC' => '/bin/sh',
      'StagerURILength' => 5
    },
    'Encoder'     => nil,
    'DisableNops' => true
  }

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
    return mod.generate_simple(OPTS6).size if mod.shortname =~ /6/
    return mod.generate_simple(OPTS).size
  end

  # Determines whether a payload generates a static sized output
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @param generation_count [Integer] The number of iterations to use to
  #   verify that the size is static.
  # @return [Integer]
  def self.is_dynamic?(mod, generation_count=5)
    [*(1..generation_count)].map do |x|
      if mod.shortname =~ /6/
        mod.generate_simple(OPTS6).size
      else
        mod.generate_simple(OPTS).size
      end
    end.uniq.length != 1
  end

  # Determines whether a payload's CachedSize is up to date
  #
  # @param mod [Msf::Payload] The class of the payload module to update
  # @return [Boolean]
  def self.is_cached_size_accurate?(mod)
    return true if mod.dynamic_size? && is_dynamic?(mod)
    return false if mod.cached_size.nil?
    if mod.shortname =~ /6/
      mod.cached_size == mod.generate_simple(OPTS6).size
    else
      mod.cached_size == mod.generate_simple(OPTS).size
    end
  end

end

end
end
