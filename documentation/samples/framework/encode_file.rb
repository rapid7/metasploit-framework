#!/usr/bin/env ruby
#
# $Id$
#
# This sample demonstrates how a file can be encoded using a framework
# encoder.
#
# $Revision$
#

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))

require 'msf/base'

if (ARGV.empty?)
  puts "Usage: #{File.basename(__FILE__)} encoder_name file_name format"
  exit
end

framework = Msf::Simple::Framework.create

begin
  # Create the encoder instance.
  mod = framework.encoders.create(ARGV.shift)

  puts(Msf::Simple::Buffer.transform(
    mod.encode(IO.read(ARGV.shift)), ARGV.shift || 'ruby'))
rescue
  puts "Error: #{$!}\n\n#{$@.join("\n")}"
end
