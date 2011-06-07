#!/usr/bin/env ruby
#
# $Id$
#
# This script lists each module with its references
#
# $Revision$
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'
require 'msf/ui'
require 'msf/base'


sort=0
filter= 'All'
filters= ['All','Exploit','Payload','Post','NOP','Encoder','Auxiliary']
types = ['All','URL','CVE','OSVDB','BID','MSB','NSS','US-CERT-VU']
type='All'
reg=0
regex= ''

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
		unless filters.include?(val)
			puts "Invalid Filter Supplied: #{val}"
			puts "Please use one of these: [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary]"
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
		reg=1
		regex = val
	end

}

puts "Type: #{type}"

Indent = '    '

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create('DisableDatabase' => true)

tbl = Rex::Ui::Text::Table.new(
	'Header'  => 'Module References',
	'Indent'  => Indent.length,
	'Columns' => [ 'Module', 'Reference' ]
)

if filter=='Payload' or filter=='All'
	$framework.payloads.each_module { |name, mod|
		x = mod.new
		x.references.each do |r|
			if type=='All' or type==r.ctx_id
				ref = r.ctx_id + '-' + r.ctx_val
				if reg==0 or ref=~/#{regex}/
					tbl << [ 'payload/' + name, ref ]
				end
			end
		end
	}
end

if filter=='Exploit' or filter=='All'
	$framework.exploits.each_module { |name, mod|
		x = mod.new
		x.references.each do |r|
			if type=='All' or type==r.ctx_id
				ref = r.ctx_id + '-' + r.ctx_val
				if reg==0 or ref=~/#{regex}/
					tbl << [ 'exploit/' + name, ref ]
				end
			end
		end
	}
end

if filter=='NOP' or filter=='All'
	$framework.nops.each_module { |name, mod|
		x = mod.new
		x.references.each do |r|
			if type=='All' or type==r.ctx_id
				ref = r.ctx_id + '-' + r.ctx_val
				if reg==0 or ref=~/#{regex}/
					tbl << [ 'nop/' + name, ref ]
				end
			end
		end
	}
end

if filter=='Encoder' or filter=='All'
	$framework.encoders.each_module { |name, mod|
		x = mod.new
		x.references.each do |r|
			if type=='All' or type==r.ctx_id
				ref = r.ctx_id + '-' + r.ctx_val
				if reg==0 or ref=~/#{regex}/
					tbl << [ 'encoder/' + name, ref ]
				end
			end
		end
	}
end

if filter=='Auxiliary' or filter=='All'
	$framework.auxiliary.each_module { |name, mod|
		x = mod.new
		x.references.each do |r|
			if type=='All' or type==r.ctx_id
				ref = r.ctx_id + '-' + r.ctx_val
				if reg==0 or ref=~/#{regex}/
					tbl << [ 'auxiliary/' + name, ref ]
				end
			end
		end
	}
end

if filter=='Post' or filter=='All'
	$framework.post.each_module { |name, mod|
		x = mod.new
		x.references.each do |r|
			if type=='All' or type==r.ctx_id
				ref = r.ctx_id + '-' + r.ctx_val
				if reg==0 or ref=~/#{regex}/
					tbl << [ 'post/' + name, ref ]
				end
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
