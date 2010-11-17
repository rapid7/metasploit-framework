#!/usr/bin/env ruby
#
# $Id$
#
# This script lists all modules with their mixins. Handy for finding different "kinds" of modules.
#
# $Revision$
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

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
