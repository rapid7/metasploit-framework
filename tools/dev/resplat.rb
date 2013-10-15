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
  file_util = ""
  begin
    file_util = %x{which file}.to_s.chomp
  rescue Errno::ENOENT
  end
  if File.executable? file_util
    file_fingerprint = %x{#{file_util} #{fname}}
    !!(file_fingerprint =~ /Ruby script/)
  end
end

def resplat(line)
  if line =~ /This file is part of the Metasploit Framework/
    return "# This module requires Metasploit: http//metasploit.com/download\n"
  elsif line =~ /redistribution and commercial/
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
    when /^[\x20\x09]*# This file is part of the Metasploit Framework and may be subject to/, /^[\x20\x09]*# redistribution and commercial restrictions\. Please see the Metasploit/, /^[\x20\x09]*# web site for more information on licensing and terms of use\./, /^[\x20\x09]*#   http:\/\/metasploit.com\//
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
