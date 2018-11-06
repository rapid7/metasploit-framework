# -*- coding: binary -*-
# Usage:
# ruby examples/ifconfig.rb

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'

iface = ARGV[0] || PacketFu::Utils.default_int
config = PacketFu::Utils.ifconfig(iface)
print "#{RUBY_PLATFORM} => "
p config
