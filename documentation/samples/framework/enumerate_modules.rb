#!/usr/bin/env ruby
#
# $Id$
#
# This sample demonstrates enumerating all of the modules in the framework and
# displays their module type and reference name.
#
# $Revision$
#

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))

require 'msf/base'

framework = Msf::Simple::Framework.create

# Enumerate each module in the framework.
framework.modules.each_module { |name, mod|
  puts "#{mod.type}: #{name}"
}
