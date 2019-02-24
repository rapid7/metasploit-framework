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
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'msf/base'

sort = 0
filter = 'All'
filters = ['all','exploit','payload','post','nOP','encoder','auxiliary']
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

# Always disable the database (we never need it just to list module
# information).
framework_opts = { 'DisableDatabase' => true }

# If the user only wants a particular module type, no need to load the others
if filter.downcase != 'all'
  framework_opts[:module_types] = [ filter.downcase ]
end

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create(framework_opts)


tbl = Rex::Text::Table.new(
  'Header'  => 'Module References',
  'Indent'  => Indent.length,
  'Columns' => [ 'Module', 'Reference' ]
)

names = {}

$framework.modules.each { |name, mod|
  x = mod.new
  x.author.each do |r|
    r = r.to_s
    if regex.nil? or r =~ regex
      tbl << [ x.fullname, r ]
      names[r] ||= 0
      names[r] += 1
    end
  end
}


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
