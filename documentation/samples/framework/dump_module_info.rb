#!/usr/bin/env ruby
#
# This sample demonstrates how a module's information can be easily serialized
# to a readable format.
#

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))

require 'msf/base'

if (ARGV.empty?)
	puts "Usage: #{File.basename(__FILE__)} module_name"
	exit
end

framework = Msf::Simple::Framework.create

begin
	# Create the module instance.
	mod = framework.modules.create(ARGV.shift)

	# Dump the module's information in readable text format.
	puts Msf::Serializer::ReadableText.dump_module(mod)
rescue
	puts "Error: #{$!}\n\n#{$@.join("\n")}"
end
