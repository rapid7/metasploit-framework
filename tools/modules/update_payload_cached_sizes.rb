#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script updates the CachedSize constants in payload modules
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

gem 'rex-text'

require 'rex'
require 'msf/ui'
require 'msf/base'
require 'msf/util/payload_cached_size'

# Initialize the simplified framework instance.
framework = Msf::Simple::Framework.create('DisableDatabase' => true)

framework.payloads.each_module do |name, mod|
  next if name =~ /generic/
  mod_inst = framework.payloads.create(name)
  #mod_inst.datastore.merge!(framework.datastore)
  next if Msf::Util::PayloadCachedSize.is_cached_size_accurate?(mod_inst)
  $stdout.puts "[*] Updating the CacheSize for #{mod.file_path}..."
  Msf::Util::PayloadCachedSize.update_module_cached_size(mod_inst)
end
