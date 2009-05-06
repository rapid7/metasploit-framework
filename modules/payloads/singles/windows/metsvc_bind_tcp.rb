##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/meterpreter'

module Metasploit3

	include Msf::Payload::Windows
	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Windows Meterpreter Service, Bind TCP',
			'Version'       => '$Revision$',
			'Description'   => 'Stub payload for interacting with a Meterpreter Service',
			'Author'        => 'hdm',
			'License'       => MSF_LICENSE,
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::Meterpreter,
			'Payload'       =>
				{
					'Offsets' => {},
					'Payload' => ""
				}
			))
	end

end
