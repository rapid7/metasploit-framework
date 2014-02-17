#!/usr/bin/env ruby
#
#
# This script takes a list of ranges and converts it to a per line ip list
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'msfenv'
require 'rex'


f = File.open('rangelist.txt', 'r')
w = File.open('iplist.txt', 'a')

f.each_line do |range|
        ips = Rex::Socket::RangeWalker.new(range)
        ips.each do |ip|
                w.puts ip
        end
end
f.close
w.close
