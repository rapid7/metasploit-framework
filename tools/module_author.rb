#!/usr/bin/env ruby
#
# $Id$
# $Revision$
#
# This script lists each module by its author(s) and
# the number of modules per author
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'
require 'msf/ui'
require 'msf/base'

sort=0
filter= 'All'
filters= ['All','Exploit','Payload','Post','NOP','Encoder','Auxiliary']
reg=0
regex= ''

opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-s" => [ false, "Sort by Author instead of Module Type."],
	"-r" => [ false, "Reverse Sort"],
	"-f" => [ true, "Filter based on Module Type [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary] (Default = All)."],
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
		unless filters.include?(val)
			puts "Invalid Filter Supplied: #{val}"
			puts "Please use one of these: [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary]"
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

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create('DisableDatabase' => true)

tbl = Rex::Ui::Text::Table.new(
	'Header'  => 'Module References',
	'Indent'  => Indent.length,
	'Columns' => [ 'Module', 'Reference' ]
)

names = {}

if filter=='Payload' or filter=='All'
	$framework.payloads.each_module { |name, mod|
		x = mod.new
		x.author.each do |r|
			r = r.to_s
			if reg==0 or r=~/#{regex}/
				tbl << [ 'payload/' + name, r ]
				names[r]||=0; names[r]+=1
			end
		end
	}
end

if filter=='Exploit' or filter=='All'
	$framework.exploits.each_module { |name, mod|
		x = mod.new
		x.author.each do |r|
			r = r.to_s
			if reg==0 or r=~/#{regex}/
				tbl << [ 'exploit/' + name, r ]
				names[r]||=0; names[r]+=1
			end
		end
	}
end

if filter=='NOP' or filter=='All'
	$framework.nops.each_module { |name, mod|
		x = mod.new
		x.author.each do |r|
			r = r.to_s
			if reg==0 or r=~/#{regex}/
				tbl << [ 'nop/' + name, r ]
				names[r]||=0; names[r]+=1
			end
		end
	}
end

if filter=='Encoder' or filter=='All'
	$framework.encoders.each_module { |name, mod|
		x = mod.new
		x.author.each do |r|
			r = r.to_s
			if reg==0 or r=~/#{regex}/
				tbl << [ 'encoder/' + name, r ]
				names[r]||=0; names[r]+=1
			end
		end
	}
end

if filter=='Auxiliary' or filter=='All'
	$framework.auxiliary.each_module { |name, mod|
		x = mod.new
		x.author.each do |r|
			r = r.to_s
			if reg==0 or r=~/#{regex}/
				tbl << [ 'auxiliary/' + name, r ]
				names[r]||=0; names[r]+=1
			end
		end
	}
end

if filter=='Post' or filter=='All'
	$framework.post.each_module { |name, mod|
		x = mod.new
		x.author.each do |r|
			r = r.to_s
			if reg==0 or r=~/#{regex}/
				tbl << [ 'post/' + name, r ]
				names[r]||=0; names[r]+=1
			end
		end
	}
end

if sort == 1
	tbl.sort_rows(1)
end


if sort == 2
	tbl.sort_rows(1)
	tbl.rows.reverse
end

puts tbl.to_s


tbl = Rex::Ui::Text::Table.new(
	'Header'  => 'Module Count by Author',
	'Indent'  => Indent.length,
	'Columns' => [ 'Count', 'Name' ]
)
names.keys.sort {|a,b| names[b] <=> names[a] }.each do |name|
	tbl << [ names[name].to_s, name ]
end

puts tbl.to_s
