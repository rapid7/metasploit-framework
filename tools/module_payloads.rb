#!/usr/bin/env ruby
#
# $Id$
#
# This script lists each exploit module by its compatible payloads
#
# $Revision$
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'msf/base'

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create('DisableDatabase' => true)

$framework.exploits.each_module { |name, mod|
  x = mod.new

  x.compatible_payloads.map{|n, m|
    puts "#{x.refname.ljust 40} - #{n}"
  }
}

