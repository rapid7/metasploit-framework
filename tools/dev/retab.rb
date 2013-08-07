#!/usr/bin/env ruby
# -*- coding: binary -*-

# Replace leading tabs with 2-width spaces.
# I'm sure there's a sed/awk/perl oneliner that's
# a million times better but this is more readable for me.

require 'fileutils'
require 'find'

dir = ARGV[0] || "."
raise ArgumentError, "Need a filename or directory" unless (dir and File.readable? dir)

Find.find(dir) do |infile|
  next unless File.file? infile
  next unless infile =~ /rb$/
outfile = infile
backup = "#{infile}.notab"
FileUtils.cp infile, backup

data = File.open(infile, "rb") {|f| f.read f.stat.size}
fixed = []
data.each_line do |line|
  fixed << line
  next unless line =~ /^\x09/
  index = []
  i = 0
  line.each_char do |char|
    break unless char =~ /[\x20\x09]/
    index << i if char == "\x09"
    i += 1
  end
  index.reverse.each do |idx|
    line[idx] = "  "
  end
  fixed[-1] = line
end

fh = File.open(outfile, "wb")
fh.write fixed.join
fh.close
puts "Retabbed #{fh.path}"
end
