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

# Initialize the simplified framework instance.
framework = Msf::Simple::Framework.create('DisableDatabase' => true)
exceptions = []
framework.payloads.each_module do |name, mod|
  begin
    next if name =~ /generic/
    mod_inst = framework.payloads.create(name)
    #mod_inst.datastore.merge!(framework.datastore)
    next if Msf::Util::PayloadCachedSize.is_cached_size_accurate?(mod_inst)
    $stdout.puts "[*] Updating the CacheSize for #{mod.file_path}..."
    Msf::Util::PayloadCachedSize.update_module_cached_size(mod_inst)
  rescue => e
    exceptions << [ e, name ]
    next
  end
end

exceptions.each do |e, name|
  print_error("Caught Error while updating #{name}:\n#{e}")
  elog(e)
end
exit(1) unless exceptions.empty?
