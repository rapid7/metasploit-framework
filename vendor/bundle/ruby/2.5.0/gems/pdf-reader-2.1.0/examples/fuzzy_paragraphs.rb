#!/usr/bin/env ruby
# coding: utf-8

# Extract an (imperfect) array of paragraphs divided somewhat
# arbitrarily on line length. 

require 'pdf/reader'

reader = PDF::Reader.new('somefile.pdf')

paragraph = ""
paragraphs = []
reader.pages.each do |page|
  lines = page.text.scan(/^.+/)
  lines.each do |line|
    if line.length > 55
      paragraph += " #{line}"
    else
      paragraph += " #{line}"
      paragraphs << paragraph
      paragraph = ""
    end
  end
end
