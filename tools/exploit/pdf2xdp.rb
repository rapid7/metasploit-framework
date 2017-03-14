#!/usr/bin/env ruby

# This script converts a PDF file to an equivalent XML Data Package file,
# which can be opened by Adobe Reader as well and typically escapes AV
# detection better than a "normal" PDF
#
# Alexander 'alech' Klink, 2011
# public domain / CC-0

require 'base64'

pdf = ARGV.shift
xdp = ARGV.shift

if ! xdp then
  STDERR.puts "    Usage: #{$0} input.pdf output.xdp"
  exit 1
end

pdf_content = begin
  File.read(pdf)
rescue
  STDERR.puts "Could not read input PDF file: #{$!}"
  exit 2
end

xdp_out = begin
  open xdp, 'w'
rescue
  STDERR.puts "Could not open output XDP file: #{$!}"
  exit 3
end

xdp_out.print '<?xml version="1.0"?><?xfa ?><xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><pdf xmlns="http://ns.adobe.com/xdp/pdf/"><document><chunk>'
xdp_out.print Base64.encode64(pdf_content)
xdp_out.print '</chunk></document></pdf></xdp:xdp>'
