#!/usr/bin/env ruby
# coding: utf-8

# Extract metadata only

require 'rubygems'
require 'pdf/reader'

filename = File.expand_path(File.dirname(__FILE__)) + "/../spec/data/cross_ref_stream.pdf"

PDF::Reader.open(filename) do |reader|
  puts reader.info.inspect
  puts reader.metadata.inspect
end
