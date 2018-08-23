#!/usr/bin/env ruby

#
# This script identifies exploit modules that do have a
# BID, OSVDB, or ZDI reference, but are lacking a CVE
# reference


modref = File.join(__dir__,"module_reference.rb")
f = %x{#{modref} -F exploit}
exploits = {}

f.each_line do |line|
  path,ref = line.strip.split
  next unless path =~ /^exploit/
  exploits[path] ||= []
  exploits[path] << ref unless exploits[path].include? ref
end

exploits.each do |exploit|
  path = exploit.first
  refs = exploit.last
  qualified_refs = refs.grep(/^(BID|OSVDB|ZDI)-/)
  next if qualified_refs.empty?
  missing_cve = refs.grep(/^CVE-[0-9]/).empty?
  puts "#{path} | #{qualified_refs.join(", ")}" if missing_cve
end

