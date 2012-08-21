# -*- coding: binary -*-
require 'msf/core/post/windows/registry'

module Msf
class Post
module Windows

module WindowsServices

	include ::Msf::Post::Windows::Registry
	#
	# List all Windows Services present. Returns an Array containing the names
	# of the services.
	#
	def service_list
		serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		threadnum = 0
		a =[]
		services = []
		registry_enumkeys(serviceskey).each do |s|
			if threadnum < 10
				a.push(::Thread.new(s) { |sk|
						begin
							srvtype = registry_getvaldata("#{serviceskey}\\#{sk}","Type").to_s
							if srvtype =~ /32|16/
								services << sk
							end
						rescue
						end
					})
				threadnum += 1
			else
				sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
				threadnum = 0
			end
		end

		return services
	end

	#
	# Get Windows Service information.
	#
	# Information returned in a hash with display name, startup mode and
	# command executed by the service. Service name is case sensitive.  Hash
	# keys are Name, Start, Command and Credentials.
	#
	def service_info(name)
		service = {}
		servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
		service["Name"] = registry_getvaldata(servicekey,"DisplayName").to_s
		srvstart = registry_getvaldata(servicekey,"Start").to_i
		if srvstart == 2
			service["Startup"] = "Auto"
		elsif srvstart == 3
			service["Startup"] = "Manual"
		elsif srvstart == 4
			service["Startup"] = "Disabled"
		end
		service["Command"] = registry_getvaldata(servicekey,"ImagePath").to_s
		service["Credentials"] = registry_getvaldata(servicekey,"ObjectName").to_s
		return service
	end

	#
	# Changes a given service startup mode, name must be provided and the mode.
	#
	# Mode is a string with either auto, manual or disable for the
	# corresponding setting. The name of the service is case sensitive.
	#
	def service_change_startup(name,mode)
		servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
		case mode.downcase
		when "auto" then
			registry_setvaldata(servicekey,"Start","2","REG_DWORD")
		when "manual" then
			registry_setvaldata(servicekey,"Start","3","REG_DWORD")
		when "disable" then
			registry_setvaldata(servicekey,"Start","4","REG_DWORD")
		end
	end

	#
	# Create a service that runs it's own process.
	#
	# It takes as values the service name as string, the display name as
	# string, the path of the executable on the host that will execute at
	# startup as string and the startup type as an integer of 2 for Auto, 3 for
	# Manual or 4 for Disable, default Auto.
	#
	def service_create(name, display_name, executable_on_host, startup=2, server=nil)
		machine_str = server ? "\\\\#{server}" : nil
		adv = session.railgun.advapi32
		manag = adv.OpenSCManagerA(machine_str,nil,0x13)
		if(manag["return"] != 0)
			# SC_HANDLE WINAPI CreateService(
			#  __in       SC_HANDLE hSCManager,
			#  __in       LPCTSTR lpServiceName,
			# __in_opt   LPCTSTR lpDisplayName,
			#  __in       DWORD dwDesiredAccess,
			#  __in       DWORD dwServiceType,
			#  __in       DWORD dwStartType,
			#  __in       DWORD dwErrorControl,
			#  __in_opt   LPCTSTR lpBinaryPathName,
			#  __in_opt   LPCTSTR lpLoadOrderGroup,
			#  __out_opt  LPDWORD lpdwTagId,
			#  __in_opt   LPCTSTR lpDependencies,
			#  __in_opt   LPCTSTR lpServiceStartName,
			#  __in_opt   LPCTSTR lpPassword
			#);
			# SC_MANAGER_CREATE_SERVICE = 0x0002
			newservice = adv.CreateServiceA(manag["return"],name,display_name,
				0x0010,0X00000010,startup,0,executable_on_host,nil,nil,nil,nil,nil)
			adv.CloseServiceHandle(newservice["return"])
			adv.CloseServiceHandle(manag["return"])
			#SERVICE_START=0x0010  SERVICE_WIN32_OWN_PROCESS= 0X00000010
			#SERVICE_AUTO_START = 2 SERVICE_ERROR_IGNORE = 0
			if newservice["GetLastError"] == 0
				return true
			else
				return false
			end
		else
			raise "Could not open Service Control Manager, Access Denied"
		end
	end

	#
	# Start a service.
	#
	# Returns 0 if service started, 1 if service is already started and 2 if
	# service is disabled.
	#
	def service_start(name, server=nil)
		machine_str = server ? "\\\\#{server}" : nil
		adv = session.railgun.advapi32
		manag = adv.OpenSCManagerA(machine_str,nil,1)
		if(manag["return"] == 0)
			raise "Could not open Service Control Manager, Access Denied"
		end
		#open with  SERVICE_START (0x0010)
		servhandleret = adv.OpenServiceA(manag["return"],name,0x10)
		if(servhandleret["return"] == 0)
			adv.CloseServiceHandle(manag["return"])
			raise "Could not Open Service, Access Denied"
		end
		retval = adv.StartServiceA(servhandleret["return"],0,nil)
		adv.CloseServiceHandle(servhandleret["return"])
		adv.CloseServiceHandle(manag["return"])
		if retval["GetLastError"] == 0
			return 0
		elsif retval["GetLastError"] == 1056
			return 1
		elsif retval["GetLastError"] == 1058
			return 2
		end
	end

	#
	# Stop a service.
	#
	# Returns 0 if service is stopped successfully, 1 if service is already
	# stopped or disabled and 2 if the service can not be stopped.
	#
	def service_stop(name, server=nil)
		machine_str = server ? "\\\\#{server}" : nil
		adv = session.railgun.advapi32
		manag = adv.OpenSCManagerA(machine_str,nil,1)
		if(manag["return"] == 0)
			raise "Could not open Service Control Manager, Access Denied"
		end
		#open with  SERVICE_STOP (0x0020)
		servhandleret = adv.OpenServiceA(manag["return"],name,0x30)
		if(servhandleret["return"] == 0)
			adv.CloseServiceHandle(manag["return"])
			raise "Could not Open Service, Access Denied"
		end
		retval = adv.ControlService(servhandleret["return"],1,56)
		adv.CloseServiceHandle(servhandleret["return"])
		adv.CloseServiceHandle(manag["return"])
		if retval["GetLastError"] == 0
			return 0
		elsif retval["GetLastError"] == 1062
			return 1
		elsif retval["GetLastError"] == 1052
			return 2
		end
	end

	#
	# Delete a service.
	#
	def service_delete(name, server=nil)
		machine_str = server ? "\\\\#{server}" : nil
		adv = session.railgun.advapi32

		# #define SC_MANAGER_ALL_ACCESS 0xF003F
		manag = adv.OpenSCManagerA(machine_str,nil,0xF003F)
		if (manag["return"] == 0)
			raise "Could not open Service Control Manager, Access Denied"
		end

		# Now to grab a handle to the service.
		# Thank you, Wine project for defining the DELETE constant since it,
		# and all its friends, are missing from the MSDN docs.
		# #define DELETE                     0x00010000
		servhandleret = adv.OpenServiceA(manag["return"],name,0x10000)
		if (servhandleret["return"] == 0)
			adv.CloseServiceHandle(manag["return"])
			raise "Could not Open Service, Access Denied"
		end

		# Lastly, delete it
		adv.DeleteService(servhandleret["return"])

		adv.CloseServiceHandle(manag["return"])
		adv.CloseServiceHandle(servhandleret["return"])
	end
end

end
end
end
