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
	'DisableDatabase' => true
)

# Process special var/val pairs...
Msf::Ui::Common.process_cli_arguments($framework, ARGV)

options = ARGV.join(',')

tbl = Rex::Ui::Text::Table.new(
	'Header'  => 'Payload Lengths',
	'Indent'  => Indent.length,
	'Columns' => [ 'Payload', 'Length' ]
)

enc = nil

$framework.payloads.each_module { |payload_name, mod|

	len = 'Error: Unknown error!'

	begin
		# Create the payload instance
		payload = mod.new
		raise "Invalid payload" if not payload

		# Set the variables from the cmd line
		payload.datastore.import_options_from_s(options)

		# Skip non-specified architectures
		if (ds_arch = payload.datastore['ARCH'])
			next if not payload.arch?(ds_arch)
		end

		# Skip non-specified platforms
		if (ds_plat = payload.datastore['PLATFORM'])
			ds_plat = Msf::Module::PlatformList.transform(ds_plat)
			next if not payload.platform.supports?(ds_plat)
		end

		len = payload.size
		if len > 0
			len = len.to_s
		else
			len = "Error: Empty payload"
		end
	rescue
		len = "Error: #{$!}"
	end

	tbl << [ payload_name, len ]
}

puts tbl.to_s
