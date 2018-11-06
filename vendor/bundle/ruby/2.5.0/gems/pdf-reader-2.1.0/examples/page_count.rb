#!/usr/bin/env ruby
# coding: utf-8

# A simple app to count the number of pages in a PDF File.

require 'rubygems'
require 'pdf/reader'

filename = File.expand_path(File.dirname(__FILE__)) + "/../spec/data/cross_ref_stream.pdf"

PDF::Reader.open(filename) do |reader|
  puts "#{reader.page_count} page(s)"
end
