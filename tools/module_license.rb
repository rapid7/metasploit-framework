#!/usr/bin/env ruby
#
# $Id$
#
# This script lists each module by its licensing terms
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

def lic_short(l)
  if (l.class == Array)
    l = l[0]
  end

  case l
  when MSF_LICENSE
    'MSF'
  when GPL_LICENSE
    'GPL'
  when BSD_LICENSE
    'BSD'
  when ARTISTIC_LICENSE
    'ART'
  else
    'UNK'
  end
end


sort=0
filter= 'All'
filters = ['all','exploit','payload','post','nop','encoder','auxiliary']
reg=0
regex= ''

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-s" => [ false, "Sort by License instead of Module Type."],
  "-r" => [ false, "Reverse Sort"],
  "-f" => [ true, "Filter based on Module Type [#{filters.map{|f|f.capitalize}.join(", ")}] (Default = All)."],
  "-x" => [ true, "String or RegEx to try and match against the License Field"]
)

opts.parse(ARGV) { |opt, idx, val|
  case opt
  when "-h"
    puts "\nMetasploit Script for Displaying Module License information."
    puts "=========================================================="
    puts opts.usage
    exit
  when "-s"
    puts "Sorting by License"
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
    reg=1
    regex = val
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
  'Header'  => 'Licensed Modules',
  'Indent'  => Indent.length,
  'Columns' => [ 'License','Type', 'Name' ]
)

licenses = {}

$framework.modules.each { |name, mod|
  x = mod.new
  lictype = lic_short(x.license)
  if reg==0 or lictype=~/#{regex}/
    tbl << [ lictype, mod.type.capitalize, name ]
  end
}


if sort == 1
  tbl.sort_rows(0)
end


if sort == 2
  tbl.sort_rows(1)
  tbl.rows.reverse
end

puts tbl.to_s
