#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script lists each module by the default ports it uses
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create('DisableDatabase' => true)
# XXX: this is weird, merging module sets together for different module types could lead to unforseen issues
all_modules = $framework.exploits.merge($framework.auxiliary)
all_ports = {}

all_modules.each_module { |name, mod|
  x = mod.new
  ports = []

  if x.datastore['RPORT']
    ports << x.datastore['RPORT']
  end

  if(x.respond_to?('autofilter_ports'))
    x.autofilter_ports.each do |rport|
      ports << rport
    end
  end
  ports = ports.map{|p| p.to_i}
  ports.uniq!
  ports.sort{|a,b| a <=> b}.each do |rport|
    # Just record the first occurrence.
    all_ports[rport] = x.fullname unless all_ports[rport]
  end
}

all_ports.sort.each { |k,v|
  puts "%5s # %s" % [k,v]
}
