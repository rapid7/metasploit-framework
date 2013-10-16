#!/usr/bin/env ruby
# -*- coding: binary -*-

# Replace comment splat with something shorter and
# more sensible.
#
# Usage:
# metasploit-framework$ ./tools/dev/resplat.rb [path]
#
# Some cargo-culting of tools/dev/retab.rb

require 'fileutils'
require 'find'

dir = ARGV[0] || "."

raise ArgumentError, "Need a filename or directory" unless (dir and File.readable? dir)

def is_ruby?(fname)
  return true if fname =~ /\.rb$/
end

def resplat(line)
  if line =~ /This file is part of the Metasploit Framework/
    return "# This module requires Metasploit: http//metasploit.com/download\n"
  elsif line =~ /# redistribution and commercial restrictions\./
    return "# Current source: https://github.com/rapid7/metasploit-framework\n"
  else
    return nil
  end
end

Find.find(dir) do |infile|
  next if infile =~ /\.git[\x5c\x2f]/
  next unless File.file? infile
  next unless is_ruby? infile
  outfile = infile

  data = File.open(infile, "rb") {|f| f.read f.stat.size}
  fixed = []
  data.each_line do |line|
    case line
    when /^[\s]*#( ##)? This file is part of the Metasploit Framework and may be subject to/, /^[\s]*# redistribution and commercial restrictions\. Please see the Metasploit/, /^[\s]*# web site for more information on licensing and terms of use\./, /^[\s]*#[\s]{1,3}http:\/\/metasploit.com\/(framework\/)?/, /^# Framework web site for more information on licensing and terms of use./
      new_line = resplat(line)
      fixed << new_line if new_line
    else
      fixed << line
    end
  end

  fh = File.open(outfile, "wb")
  fh.write fixed.join
  fh.close
  puts "Resplatted #{fh.path}"
end
