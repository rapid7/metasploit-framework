#!/usr/bin/env ruby
#
# Tested on:
#
#   ruby-1.9.3-head [ x86_64 ]  
#   ruby-1.9.3-p484 [ x86_64 ]

# Okay so the regular test/unit stuff screws up some of my
# meta magic. I need to move these over to spec and see
# if they're any better. In the meantime, behold my
# ghetto test exec()'er. It all passes with this,
# so I'm just going to go ahead and assume the testing
# methodolgy is flawed. TODO: rewrite all this for spec
# and incidentally get the gem to test like it's supposed
# to.

$:.unshift File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu'
puts "Testing PacketFu v#{PacketFu::VERSION}"
dir = Dir.new(File.dirname(__FILE__))

dir.each { |file|
  next unless File.file? file
  next unless file[/^test_.*rb$/]
  next if file == $0
  puts "Running #{file}..."
  cmd = %x{ruby #{file}}
  if cmd[/ 0 failures/] && cmd[/ 0 errors/] 
    puts "#{file}: All passed"
  else
    puts "File: #{file} had failures or errors:"
    puts "-" * 80
    puts cmd
    puts "-" * 80
  end
}

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
