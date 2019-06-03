#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script lists each module by its author(s) and
# the number of modules per author
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))

require 'rex'
require 'json'

FILENAME = 'db/modules_metadata_base.json'

sort = 0
filter = 'All'
filters = ['all','exploit','payload','post','nop','encoder','auxiliary', 'evasion']
reg = 0
regex = nil

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-s" => [ false, "Sort by Author instead of Module Type."],
  "-r" => [ false, "Reverse Sort"],
  "-f" => [ true, "Filter based on Module Type [#{filters.map{|f|f.capitalize}.join(", ")}] (Default = All)."],
  "-x" => [ true, "String or RegEx to try and match against the Author Field"]
)

opts.parse(ARGV) { |opt, idx, val|
  case opt
  when "-h"
    puts "\nMetasploit Script for Displaying Module Author information."
    puts "=========================================================="
    puts opts.usage
    exit
  when "-s"
    puts "Sorting by Author"
    sort = 1
  when "-r"
    puts "Reverse Sorting"
    sort = 2
  when "-f"
    unless filters.include?(val.downcase)
      puts "Invalid Filter Supplied: #{val}"
      puts "Please use one of these: #{filters.map{|f|f.capitalize}.join(", ")}"
      exit
    end
    puts "Module Filter: #{val}"
    filter = val
  when "-x"
    puts "Regex: #{val}"
    regex = Regexp.new(val)
  end

}


Indent = '    '

tbl = Rex::Text::Table.new(
  'Header'  => 'Module References',
  'Indent'  => Indent.length,
  'Columns' => [ 'Module', 'Reference' ]
)

names = {}

local_modules = JSON.parse(File.read(FILENAME)) # get cache file location from framework?

local_modules.each do |_module_key, local_module|
  local_module['author'].each do |r|
    next if filter.downcase != 'all' && local_module['type'] != filter.downcase
    if regex.nil? or r =~ regex
      tbl << [ local_module['full_name'], r ]
      names[r] ||= 0
      names[r] += 1
    end
  end
end

if sort == 1
  tbl.sort_rows(1)
end


if sort == 2
  tbl.sort_rows(1)
  tbl.rows.reverse
end

puts tbl.to_s

tbl = Rex::Text::Table.new(
  'Header'  => 'Module Count by Author',
  'Indent'  => Indent.length,
  'Columns' => [ 'Count', 'Name' ]
)
names.keys.sort {|a,b| names[b] <=> names[a] }.each do |name|
  tbl << [ names[name].to_s, name ]
end

puts
puts tbl.to_s
