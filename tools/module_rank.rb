#!/usr/bin/env ruby
#
# $Id$
#
# This script lists each module with its rank
#
# $Revision$
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

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
filters= ['All','Exploit','Payload','Post','NOP','Encoder','Auxiliary']
ranks = ['Manual','Low','Average','Normal','Good','Great','Excellent']



opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-M" => [ true, "Set Maxmimum Rank [Manual,Low,Average,Normal,Good,Great,Excellent] (Default = Excellent)." ],
	"-m" => [ true, "Set Minimum Rank [Manual,Low,Average,Normal,Good,Great,Excellent] (Default = Manual)."],
	"-s" => [ false, "Sort by Rank instead of Module Type."],
	"-r" => [ false, "Reverse Sort by Rank"],
	"-f" => [ true, "Filter based on Module Type [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary] (Default = All)."]
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
		unless filters.include?(val)
			puts "Invalid Filter Supplied: #{val}"
			puts "Please use one of these: [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary]"
			exit
		end
		puts "Module Filter: #{val}"
		filter = val

	end

}


Indent = '    '

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create('DisableDatabase' => true)

tbl = Rex::Ui::Text::Table.new(
	'Header'  => 'Module Ranks',
	'Indent'  => Indent.length,
	'Columns' => [ 'Module', 'Rank' ]
)

if filter=='Payload' or filter=='All'
	$framework.payloads.each_module { |name, mod|
		x = mod.new
		modrank = x.rank
		if modrank >= minrank and modrank<= maxrank
			tbl << [ 'payload/' + name, modrank ]
		end
	
	}
end

if filter=='Exploit' or filter=='All'
	$framework.exploits.each_module { |name, mod|
		x = mod.new
		modrank = x.rank
		if modrank >= minrank and modrank<= maxrank
			tbl << [ 'exploit/' + name, modrank ]
		end
	
	
	}
end

if filter=='NOP' or filter=='All'
	$framework.nops.each_module { |name, mod|
		x = mod.new
		modrank = x.rank
		if modrank >= minrank and modrank<= maxrank
			tbl << [ 'nop/' + name, modrank ]
		end
	
	}
end

if filter=='Encoder' or filter=='All'
	$framework.encoders.each_module { |name, mod|
		x = mod.new
		modrank = x.rank
		if modrank >= minrank and modrank<= maxrank
			tbl << [ 'encoder/' + name, modrank ]
		end
	
	}
end

if filter=='Auxiliary' or filter=='All'
	$framework.auxiliary.each_module { |name, mod|
		x = mod.new
		modrank = x.rank
		if modrank >= minrank and modrank<= maxrank
			tbl << [ 'auxiliary/' + name, modrank ]
		end
	
	}
end

if filter=='Post' or filter=='All'
	$framework.post.each_module { |name, mod|
		x = mod.new
		modrank = x.rank
		if modrank >= minrank and modrank<= maxrank
			tbl << [ 'post/' + name, modrank ]
		end
	
	}
end

if sort==1
	tbl.sort_rows(1)
end

if sort=2
	tbl.sort_rows(1)
	tbl.rows.reverse
end

puts tbl.to_s
