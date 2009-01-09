#!/usr/bin/env ruby
#
# This script lists each module by its licensing terms
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

Indent = '    ' 

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create


tbl = Rex::Ui::Text::Table.new(
	'Header'  => 'Licensed Modules',
	'Indent'  => Indent.length,
	'Columns' => [ 'License','Type', 'Name' ]
)

licenses = {}

$framework.payloads.each_module { |name, mod|
	x = mod.new
	tbl << [ lic_short(x.license), 'Payload', name ]
}
$framework.exploits.each_module { |name, mod|
	x = mod.new
	tbl << [ lic_short(x.license), 'Exploit', name ]
}
$framework.nops.each_module { |name, mod|
	x = mod.new
	tbl << [ lic_short(x.license), 'Nop', name ]
}
$framework.encoders.each_module { |name, mod|
	x = mod.new
	tbl << [ lic_short(x.license), 'Encoder', name ]
}
$framework.auxiliary.each_module { |name, mod|
	x = mod.new
	tbl << [ lic_short(x.license), 'Auxiliary', name ]
}

puts tbl.to_s
