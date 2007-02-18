##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Auxiliary::Dos::Wireless::WiFun < Msf::Auxiliary

	include Exploit::Lorcon


	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Wireless Test Module',
			'Description'    => %q{
				This module is a test of the wireless packet injection system.
			Please see external/msflorcon/README for more information.
			},
			
			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$'
		))			
	end

	def run
		open_wifi
		wifi.write("X" * 1000)
	end

end
end	
