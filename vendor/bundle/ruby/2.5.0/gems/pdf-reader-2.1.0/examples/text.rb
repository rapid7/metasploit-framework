#!/usr/bin/env ruby
# coding: utf-8

# Extract all text from a single PDF

require 'rubygems'
require 'pdf/reader'

filename = File.expand_path(File.dirname(__FILE__)) + "/../spec/data/cairo-unicode.pdf"

PDF::Reader.open(filename) do |reader|
  reader.pages.each do |page|
    puts page.text
  end
end
