#!/usr/bin/env ruby
#
# $Id$
#
# This script lists each module with its references
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


sort=0
filter= 'All'
filters = ['all','exploit','payload','post','nop','encoder','auxiliary']
types = ['All','URL','CVE','OSVDB','BID','MSB','NSS','US-CERT-VU']
type='All'
match= nil

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-s" => [ false, "Sort by Reference instead of Module Type."],
  "-r" => [ false, "Reverse Sort"],
  "-f" => [ true, "Filter based on Module Type [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary] (Default = All)."],
  "-t" => [ true, "Type of Reference to sort by [All,URL,CVE,OSVDB,BID,MSB,NSS,US-CERT-VU]"],
  "-x" => [ true, "String or RegEx to try and match against the Reference Field"]

)

opts.parse(ARGV) { |opt, idx, val|
  case opt
  when "-h"
    puts "\nMetasploit Script for Displaying Module Reference information."
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
  when "-t"
    unless types.include?(val)
      puts "Invalid Type Supplied: #{val}"
      puts "Please use one of these: [All,URL,CVE,OSVDB,BID,MSB,NSS,US-CERT-VU]"
      exit
    end
    puts "Type: #{val}"
    type = val
  when "-x"
    puts "Regex: #{val}"
    match = Regexp.new(val)
  end

}

puts "Type: #{type}"

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
  'Header'  => 'Module References',
  'Indent'  => Indent.length,
  'Columns' => [ 'Module', 'Reference' ]
)

$framework.modules.each { |name, mod|
  next if match and not name =~ match

  x = mod.new
  x.references.each do |r|
    if type=='All' or type==r.ctx_id
      ref = "#{r.ctx_id}-#{r.ctx_val}"
      tbl << [ x.fullname, ref ]
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
