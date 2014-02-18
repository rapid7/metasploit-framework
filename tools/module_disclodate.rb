#!/usr/bin/env ruby
#
# $Id$
# $Revision$
#
# This script lists each module by its disclosure date
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

nilc = false
sort = 0
filter = 'All'
filters = ['all','exploit','payload','post','nop','encoder','auxiliary']
startdate = Date.new
enddate = Date.new(2525,01,01)
match = nil

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-s" => [ false, "Sort by Disclosure Date instead of Module Type."],
  "-r" => [ false, "Reverse Sort"],
  "-f" => [ true, "Filter based on Module Type [#{filters.map{|f|f.capitalize}.join(", ")}] (Default = All)."],
  "-n" => [ false, "Filter out modules that have no Disclosure Date listed."],
  "-d" => [ true, "Start of Date Range YYYY-MM-DD."],
  "-D" => [ true, "End of Date Range YYYY-MM-DD."]
)

opts.parse(ARGV) { |opt, idx, val|
  case opt
  when "-h"
    puts "\nMetasploit Script for Displaying Module Disclosure Date Information."
    puts "=========================================================="
    puts opts.usage
    exit
  when "-s"
    puts "Sorting by Disclosure Date"
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
  when "-n"
    puts "Excluding Null dates"
    nilc=1
  when "-d"
    (year,month,day) = val.split('-')
    if Date.valid_civil?(year.to_i,month.to_i,day.to_i)
      startdate= Date.new(year.to_i,month.to_i,day.to_i)
      puts "Start Date: #{startdate}"
    else
      puts "Invalid Start Date: #{val}"
      exit
    end
  when "-D"
    (year,month,day) = val.split('-')
    if Date.valid_civil?(year.to_i,month.to_i,day.to_i)
      enddate= Date.new(year.to_i,month.to_i,day.to_i)
      puts "End Date: #{enddate}"
    else
      puts "Invalid Start Date: #{val}"
      exit
    end
  else
    if opt
      puts "Unknown option"
      exit
    end
    match = Regexp.new(val)
  end

}

Indent = '  '

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
  'Header'  => 'Module References',
  'Indent'  => Indent.length,
  'Columns' => [ 'Module', 'Disclosure Date' ]
)

$framework.modules.each { |name, mod|
  next if match and not name =~ match
  x = mod.new
  if x.disclosure_date.nil?
    if nilc==1
      tbl << [ x.fullname, '' ]
    end
  else
    if x.disclosure_date >= startdate and x.disclosure_date <= enddate
      tbl << [ x.fullname, x.disclosure_date ]
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
