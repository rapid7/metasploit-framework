#!/usr/bin/env ruby
#
# $Id$
#
# This script lists each module by its licensing terms
#
# $Revision$
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

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
filters= ['All','Exploit','Payload','Post','NOP','Encoder','Auxiliary']
reg=0
regex= ''

opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-s" => [ false, "Sort by License instead of Module Type."],
	"-r" => [ false, "Reverse Sort"],
	"-f" => [ true, "Filter based on Module Type [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary] (Default = All)."],
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
	'Header'  => 'Licensed Modules',
	'Indent'  => Indent.length,
	'Columns' => [ 'License','Type', 'Name' ]
)

licenses = {}

if filter=='Payload' or filter=='All'
	$framework.payloads.each_module { |name, mod|
		x = mod.new
		lictype = lic_short(x.license)
		if reg==0 or lictype=~/#{regex}/
			tbl << [ lictype, 'Payload', name ]
		end
	}
end

if filter=='Exploit' or filter=='All'
	$framework.exploits.each_module { |name, mod|
		x = mod.new
		lictype = lic_short(x.license)
		if reg==0 or lictype=~/#{regex}/
			tbl << [ lictype, 'Exploit', name ]
		end
	}
end

if filter=='NOP' or filter=='All'
	$framework.nops.each_module { |name, mod|
		x = mod.new
		lictype = lic_short(x.license)
		if reg==0 or lictype=~/#{regex}/
			tbl << [ lictype, 'Nop', name ]
		end
	}
end

if filter=='Encoder' or filter=='All'
	$framework.encoders.each_module { |name, mod|
		x = mod.new
		lictype = lic_short(x.license)
		if reg==0 or lictype=~/#{regex}/
			tbl << [ lictype, 'Encoder', name ]
		end
	}
end

if filter=='Auxiliary' or filter=='All'
	$framework.auxiliary.each_module { |name, mod|
		x = mod.new
		lictype = lic_short(x.license)
		if reg==0 or lictype=~/#{regex}/
			tbl << [ lictype, 'Auxiliary', name ]
		end
	}
end

if filter=='Post' or filter=='All'
	$framework.post.each_module { |name, mod|
		x = mod.new
		lictype = lic_short(x.license)
		if reg==0 or lictype=~/#{regex}/
			tbl << [ lictype, 'Post', name ]
		end
	}
end

if sort == 1
	tbl.sort_rows(0)
end


if sort == 2
	tbl.sort_rows(1)
	tbl.rows.reverse
end

puts tbl.to_s
