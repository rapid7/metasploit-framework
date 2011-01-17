##
# $Id$
##

module Msf
module Sessions
module MeterpreterOptions

	def initialize(info = {})
		super(info)

		register_advanced_options(
			[
				OptBool.new('AutoLoadStdapi', [true, "Automatically load the Stdapi extension", true]),
				OptString.new('InitialAutoRunScript', [false, "An initial script to run on session creation (before AutoRunScript)", '']),
				OptString.new('AutoRunScript', [false, "A script to run automatically on session creation.", '']),
				OptBool.new('AutoSystemInfo', [true, "Automatically capture system information on initialization.", true]),
			], self.class)
	end

	#
	# Once a session is created, automatically load the stdapi extension if the
	# advanced option is set to true.
	#
	def on_session(session)
		super

		session.init_ui(self.user_input, self.user_output)

		if (datastore['AutoLoadStdapi'] == true)

			session.load_stdapi

			if datastore['AutoSystemInfo']
				session.load_session_info
			end

=begin
			admin = false
			begin
				::Timeout.timeout(30) do
					if session.railgun and session.railgun.shell32.IsUserAnAdmin()["return"] == true
						admin = true
						session.info += " (ADMIN)"
					end
				end
			rescue ::Exception
			end
=end
			if session.platform =~ /win32|win64/i
				session.load_priv rescue nil
			end
		end
		
		
		[ 'InitialAutoRunScript', 'AutoRunScript' ].each do |key|
			if (datastore[key].empty? == false)
				args = datastore[key].split
				print_status("Session ID #{session.sid} (#{session.tunnel_to_s}) processing #{key} '#{datastore[key]}'")
				run_script(session, args.shift, *args)
			end
		end

	end

	def run_script(session, script_name, *args)
		mod = session.framework.modules.create(script_name)
		if (mod and mod.type == "post")
			opts = (args + [ "SESSION=#{session.sid}" ]).join(',')
			mod.run_simple(
				# Run with whatever the default stance is for now.  At some
				# point in the future, we'll probably want a way to force a
				# module to run in the background
				#'RunAsJob' => true,
				'LocalInput'  => session.user_input,
				'LocalOutput' => session.user_output,
				'OptionStr'   => opts
			)
		else
			session.execute_script(script_name, args)
		end
	end
end
end
end

