#!/usr/bin/env ruby
#
# $Id$
# $Revision$
#
# This script lists each payload module along with its length
# NOTE: No encoding or BadChar handling is performed
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'
require 'msf/ui'
require 'msf/base'

Indent = '    '

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create(
	:module_types => [
		Msf::MODULE_PAYLOAD # , Msf::MODULE_ENCODER, Msf::MODULE_NOP 
	],
	#'DisableDatabase' => true
)

# Process special var/val pairs...
Msf::Ui::Common.process_cli_arguments($framework, ARGV)

tbl = Rex::Ui::Text::Table.new(
	'Header'  => 'Payload Lengths',
	'Indent'  => Indent.length,
	'Columns' => [ 'Payload', 'Length' ]
)

enc = nil
options = ARGV.join(',')

$framework.payloads.each_module { |payload_name, mod|

	len = 'Unknown error!'

	begin
		# Create the payload instance
		payload = $framework.payloads.create(payload_name)
		raise "Invalid payload" if not payload

		buf = payload.generate_simple(
			'Format'    => 'raw',
			'OptionStr' => options,
			'Encoder'   => enc
		)
		if buf.length > 0
			len = buf.length.to_s
		else
			len = "Error: Empty payload"
		end
	rescue
		len = "Error: #{$!}"
	end

	tbl << [ payload_name, len ]
}

puts tbl.to_s
