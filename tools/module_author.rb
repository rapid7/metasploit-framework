#!/usr/bin/env ruby
#
# This script lists each module by its licensing terms
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'
require 'msf/ui'
require 'msf/base'

Indent = '    ' 

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create

tbl = Rex::Ui::Text::Table.new(
	'Header'  => 'Module References',
	'Indent'  => Indent.length,
	'Columns' => [ 'Module', 'Reference' ]
)

licenses = {}
names = {}

$framework.payloads.each_module { |name, mod|
	x = mod.new
	x.author.each do |r|
		r = r.to_s
		tbl << [ 'payload/' + name, r ]
		names[r]||=0; names[r]+=1
	end
}

$framework.exploits.each_module { |name, mod|
	x = mod.new
	x.author.each do |r|
		r = r.to_s
		tbl << [ 'exploit/' + name, r ]
		names[r]||=0; names[r]+=1
	end
}

$framework.nops.each_module { |name, mod|
	x = mod.new
	x.author.each do |r|
		r = r.to_s
		tbl << [ 'nop/' + name, r ]
		names[r]||=0; names[r]+=1		
	end
}
$framework.encoders.each_module { |name, mod|
	x = mod.new
	x.author.each do |r|
		r = r.to_s
		tbl << [ 'encoder/' + name, r ]
		names[r]||=0; names[r]+=1		
	end
}
$framework.auxiliary.each_module { |name, mod|
	x = mod.new
	x.author.each do |r|
		r = r.to_s
		tbl << [ 'auxiliary/' + name, r ]
		names[r]||=0; names[r]+=1		
	end
}

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

