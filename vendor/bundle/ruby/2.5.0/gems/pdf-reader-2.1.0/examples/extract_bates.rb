#!/usr/bin/env ruby
# coding: utf-8

# A sample script that attempts to extract bates numbers from a PDF file.
# Bates numbers are often used to markup documents being used in legal
# cases. For more info, see http://en.wikipedia.org/wiki/Bates_numbering
#
# Acrobat 9 introduced a markup syntax that directly specifies the bates
# number for each page. For earlier versions, the easiest way to find
# the number is to look for words that match a pattern.
#
# This example attempts to extract numbers using the Acrobat 9 syntax.
# As a fall back, you can use a regular expression to look for words
# that match the numbers you expect in the page content.

require 'rubygems'
require 'pdf/reader'

class BatesReceiver

  attr_reader :numbers

  def initialize
    @numbers = []
  end

  def begin_marked_content(*args)
    return unless args.size >= 2
    return unless args.first == :Artifact
    return unless args[1][:Subtype] == :BatesN

    @numbers << args[1][:Contents]
  end
  alias :begin_marked_content_with_pl :begin_marked_content

end

filename = File.expand_path(File.dirname(__FILE__)) + "/../spec/data/cairo-basic.pdf"

PDF::Reader.open(filename) do |reader|
  reader.pages.each do |page|
    receiver = BatesReceiver.new
    page.walk(receiver)
    if receiver.numbers.empty?
      puts page.text.scan(/CC.+/)
    else
      puts receiver.numbers.inspect
    end
  end
end
