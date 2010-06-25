#!/usr/bin/env ruby
#
# $Id$
# $Revision$
#
# This script lists each module by its disclosure date
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'
require 'msf/ui'
require 'msf/base'

Indent = '  '

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create


tbl = Rex::Ui::Text::Table.new(
	'Header'  => 'Module References',
	'Indent'  => Indent.length,
	'Columns' => [ 'Module', 'Disclosure Date' ]
)


$framework.payloads.each_module { |name, mod|
	x = mod.new
	tbl << [ 'payload/' + name, x.disclosure_date ]
}

$framework.exploits.each_module { |name, mod|
	x = mod.new
	tbl << [ 'exploit/' + name, x.disclosure_date ]
}

$framework.nops.each_module { |name, mod|
	x = mod.new
	tbl << [ 'nop/' + name, x.disclosure_date ]
}

$framework.encoders.each_module { |name, mod|
	x = mod.new
	tbl << [ 'encoder/' + name, x.disclosure_date ]
}

$framework.auxiliary.each_module { |name, mod|
	x = mod.new
	tbl << [ 'auxiliary/' + name, x.disclosure_date ]
}

puts tbl.to_s
