#!/usr/bin/env ruby
# coding: utf-8

# get direct access to PDF objects

require 'pdf/reader'

filename = File.expand_path(File.dirname(__FILE__)) + "/../spec/data/cairo-unicode.pdf"

reader = PDF::Reader.new(filename)
puts reader.objects[3]
puts reader.objects[4]
