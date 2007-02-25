##
# $Id: test.rb 4419 2007-02-18 00:10:39Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

###
#
# This sample auxiliary module simply displays the selected action and
# registers a custom command that will show up when the module is used.
#
###
class Auxiliary::Sample < Msf::Auxiliary

	def initialize
		super(
			'Name'        => 'Sample Auxiliary Module',
			'Version'     => '$Revision: 4419 $',
			'Description' => 'Sample Auxiliary Module',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
					['Default Action'],
					['Another Action']
				]
		)

	end

	def run
		print_status("Running the simple auxiliary module with action #{action.name}")
	end

	def auxiliary_commands
		return { "aux_extra_command" => "Run this auxiliary test commmand" }
	end

	def cmd_aux_extra_command(*args)
		print_status("Running inside aux_extra_command()")
	end
	
end

end
