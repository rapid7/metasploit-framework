#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script lists all modules with their mixins. Handy for finding different "kinds" of modules.
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'msf/base'

def do_want(klass)
  return false if klass.class != Module
  return false if [ Kernel, ERB::Util, SNMP::BER].include?(klass)
  return false if klass.to_s.match(/^Rex::Ui::Subscriber/)

  return true
end

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create('DisableDatabase' => true)

all_modules = $framework.exploits

# If you give an argument (any argument will do), you really want a sorted
# list of mixins, regardles of the module they're in.
if ARGV[0]
  mod_hash = {}
  longest_name = 0
  all_modules.each_module do |name, mod|
    x = mod.new
    mixins = x.class.ancestors.select {|y| do_want(y) }
    mixins.each do |m|
      mod_hash[m] ||= 0
      mod_hash[m] += 1
      longest_name = m.to_s.size unless m.to_s.size < longest_name
    end
  end
  mod_hash.sort_by {|a| a[1]}.reverse.each do |arr|
    puts "%-#{longest_name}s | %d" % arr
  end
else
  # Tables kind of suck for this.
  results = []
  longest_name = 0
  all_modules.each_module do |name, mod|
    x = mod.new
    mixins = x.class.ancestors.select {|y| do_want(y) }
    results << [x.fullname, mixins.sort {|a,b| a.to_s <=> b.to_s}.join(", ")]
    longest_name = x.fullname.size if longest_name < x.fullname.size
  end
  # name | module1, module1, etc.
  results.each do |r|
    puts "%-#{longest_name}s | %s" % r
  end
end
