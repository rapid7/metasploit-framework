#!/usr/bin/env ruby
#
# $Id$
#
# This script lists each module with its rank
#
# $Revision$
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'msf/base'

ranks= Hash.new

ranks['Manual'] = 0
ranks['Low'] = 100
ranks['Average'] = 200
ranks['Normal'] = 300
ranks['Good'] = 400
ranks['Great'] = 500
ranks['Excellent'] = 600

minrank= 0
maxrank= 600
sort = 0
filter= 'All'
filters = ['all','exploit','payload','post','nop','encoder','auxiliary']

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-M" => [ true, "Set Maxmimum Rank [Manual,Low,Average,Normal,Good,Great,Excellent] (Default = Excellent)." ],
  "-m" => [ true, "Set Minimum Rank [Manual,Low,Average,Normal,Good,Great,Excellent] (Default = Manual)."],
  "-s" => [ false, "Sort by Rank instead of Module Type."],
  "-r" => [ false, "Reverse Sort by Rank"],
  "-f" => [ true, "Filter based on Module Type [#{filters.map{|f|f.capitalize}.join(", ")}] (Default = All)."],
)

opts.parse(ARGV) { |opt, idx, val|
  case opt
  when "-h"
    puts "\nMetasploit Script for Displaying Module Rank information."
    puts "=========================================================="
    puts opts.usage
    exit
  when "-M"
    unless ranks.include?(val)
      puts "Invalid Rank Supplied: #{val}"
      puts "Please use one of these: [Manual,Low,Average,Normal,Good,Great,Excellent]"
      exit
    end
    puts "Maximum Rank: #{val}"
    maxrank = ranks[val]
  when "-m"
    unless ranks.include?(val)
      puts "Invalid Rank Supplied: #{val}"
      puts "Please use one of these: [Manual,Low,Average,Normal,Good,Great,Excellent]"
      exit
    end
    puts "Minimum Rank: #{val}"
    minrank = ranks[val]
  when "-s"
    puts "Sorting by Rank"
    sort = 1
  when "-r"
    puts "Reverse Sorting by Rank"
    sort = 2
  when "-f"
    unless filters.include?(val.downcase)
      puts "Invalid Filter Supplied: #{val}"
      puts "Please use one of these: #{filters.map{|f|f.capitalize}.join(", ")}"
      exit
    end
    puts "Module Filter: #{val}"
    filter = val

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


tbl = Rex::Ui::Text::Table.new(
  'Header'  => 'Module Ranks',
  'Indent'  => Indent.length,
  'Columns' => [ 'Module', 'Rank' ]
)

$framework.modules.each { |name, mod|
  x = mod.new
  modrank = x.rank
  if modrank >= minrank and modrank<= maxrank
    tbl << [ x.fullname, modrank ]
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
