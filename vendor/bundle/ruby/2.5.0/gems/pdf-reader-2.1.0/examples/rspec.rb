#!/usr/bin/env ruby
# coding: utf-8

#  Basic RSpec of a generated PDF
#
#  USAGE: rspec -c examples/rspec.rb

require 'rubygems'
require 'pdf/reader'
require 'rspec'
require 'prawn'
require 'stringio'

describe "My generated PDF" do
  it "should have the correct text on 2 pages" do

    # generate our PDF
    pdf = Prawn::Document.new
    pdf.text "Chunky"
    pdf.start_new_page
    pdf.text "Bacon"
    io = StringIO.new(pdf.render)

    # process the PDF
    PDF::Reader.open(io) do |reader|
      reader.page_count.should eql(2)          # correct page count

      reader.page(1).text.should eql("Chunky") # correct content
      reader.page(2).text.should eql("Bacon")  # correct content
    end

  end
end
