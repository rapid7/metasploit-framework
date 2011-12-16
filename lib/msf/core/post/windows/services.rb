require 'msf/core/post/windows/registry'

module Msf
class Post
module Windows

module WindowsServices

	include Msf::Post::Windows::CliParse
	include ::Msf::Post::Windows::Registry
	
	#
	# List all Windows Services present. Returns an Array containing the names (keynames)
	# of the services, whether they are running or not.
	#

	def service_list
		if session_has_services_depend?
			meterpreter_service_list
		else
			shell_service_list
		end
	end
	
	#
	# List all running Windows Services present. Returns an Array containing the names
	# (keynames) of the services.
	#
	
	def service_list_running
		if session_has_services_depend?
			#TODO:  implement meterpreter_service_list_running
			raise NotImplementedError.new "#{__method__}"
		else
			shell_service_list_running
		end
	end

	#
	# Get Windows Service information. 
	#
	# Information returned in a hash with display name, startup mode and
	# command executed by the service. Service name is case sensitive.  Hash
	# keys are Name, Start, Command and Credentials.
	#

	def service_info(name)
		if session_has_services_depend?
			meterpreter_service_info(name)
		else
			shell_service_info(name)
		end
	end

	#
	# Changes a given service startup mode, name must be provided, mode defaults to auto.
	#
	# Mode is an int or string with either 2/auto, 3/manual or 4/disable etc for the
	# corresponding setting (see normalize_mode).
	#

	def service_change_startup(name,mode="auto")
		if session_has_services_depend?
			meterpreter_service_change_startup(name,mode)
		else
			shell_service_change_startup(name,mode)
		end
	end

	#
	# Create a service.  Returns nil if success
	#
	# It takes as values the service name as string, the display name as
	# string, the path of the executable on the host that will execute at
	# startup as string and the startup mode as an integer or string of:
	# 	2/auto for 		Auto
	# 	3/manual/demand	Manual
	# 	4/disable for 	Disable
	# See normalize_mode for details
	# Default is Auto.
	# TODO: convert args to take a hash so a variable number of options can be provided?
	#

	def service_create(name, display_name, executable_on_host, startup=2)
		if session_has_services_depend?
			meterpreter_service_create(name, display_name, executable_on_host,startup)
		else
			shell_service_create(name, display_name, executable_on_host,startup)
		end
	end
	
	#
	# Start a service.  Returns nil if success
	#
	
	def service_start(name)
		if session_has_services_depend?
			meterpreter_service_start(name)
		else
			shell_service_start(name)
		end
	end
	
	#
	# Stop a service.  Returns nil if success
	#
	
	def service_stop(name)
		if session_has_services_depend?
			meterpreter_service_stop(name)
		else
			shell_service_stop(name)
		end
	end
	
	#
	# Delete a service
	#
	# Delete a service by deleting the key in the registry (meterpreter) or sc delete <name>
	# Returns nil if success.
	#
	
	def service_delete(name)
		if session_has_services_depend?
			meterpreter_service_delete(name)
		else
			shell_service_delete(name)
		end
	end
	
	#
	# Get Windows Service config information. 
	#
	# Info returned stuffed into a hash with most service info available 
	# Service name is case sensitive.
	#
	# for non-native meterpreter:
	# Hash keys match the keys returned by sc.exe qc <service_name>, but downcased and symbolized
	# e.g returns {
	# :service_name => "winmgmt",
	# :type => "20 WIN32_SHARE_PROCESS",
	# :start_type => "2 AUTO_START",
	# <...>
	# :dependencies => "RPCSS,OTHER",
	# :service_start_name => "LocalSystem" }
	#
	
	def service_query_config(name)
		if session_has_services_depend?
			#TODO:  implement meterpreter_query_config(name)
			raise NotImplementedError.new "#{__method__}"
		else
			shell_service_query_config(name)
		end
		
	end
	
	#
	# Get extended Windows Service staus information. 
	#
	# Info returned stuffed into a hash with all available service info
	# Service name is case sensitive.
	#
	# for non-native meterpreter:
	# Hash keys match the keys returned by sc.exe queryex <service_name>, but downcased and symbolized
	# e.g returns {
	# :service_name => "winmgmt",
	# :type => "20 WIN32_SHARE_PROCESS",
	# :state => "4 RUNNING,STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN"
	# <...>
	# :pid => 1108
	# }
	
	def service_query_ex(name)
		if session_has_services_depend?
			#TODO:  implement meterpreter_service_query_ex(name)
			raise NotImplementedError.new "#{__method__}"
		else
			shell_service_query_ex(name)
		end	
	end

	#
	# Get Windows Service state only. 
	#
	# returns a string with state info such as "4 RUNNING,STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN"
	# could normalize it to just "RUNNING" if desired, but not currently
	#

	def service_query_state(name)
		if session_has_services_depend?
			#TODO:  implement meterpreter_service_query_state(name)
			raise NotImplementedError.new "#{__method__}"
		else
			shell_service_query_state(name)
		end	
	end

protected

	##
	# Native Meterpreter-specific windows service manipulation methods
	##
	
	def meterpreter_service_list
		serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		threadnum = 0
		a =[]
		services = []
		begin
			meterpreter_registry_enumkeys(serviceskey).each do |s|
 				if threadnum < 10
					a.push(::Thread.new(s) { |sk|
						begin
							srvtype = registry_getvaldata("#{serviceskey}\\#{sk}","Type").to_s
							services << sk if srvtype =~ /32|16/
						rescue
						end
					})
					threadnum += 1
				else
					sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
					threadnum = 0
				end
			end
		rescue Exception => e
			print_error("Error enumerating services.  #{e.to_s}")
		end
		return services
	end
	
	def meterpreter_service_list_running
		raise NotImplementedError.new "#{__method__}"
		#
		all_services = self.meterpreter_service_list
		run_services = []
		all_services.each do |s|
			run_services << s if s.running? # TODO:  define running? or other solution here
		end
	end

	def meterpreter_service_info(name)
		service = {}
		servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
		begin
			service["Name"] = registry_getvaldata(servicekey,"DisplayName").to_s
			service["Startup"] = normalize_mode(registry_getvaldata(servicekey,"Start").to_i)
			service["Command"] = registry_getvaldata(servicekey,"ImagePath").to_s
			service["Credentials"] = registry_getvaldata(servicekey,"ObjectName").to_s
		rescue Exception => e
			print_error("Error collecing service info.  #{e.to_s}")
			return nil
		end
		return service
	end

	def meterpreter_service_change_startup(name,mode)
		servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
		mode = normalize_mode(mode,true).to_s # the string version of the int, e.g. "2"
		begin
			registry_setvaldata(servicekey,'Start',mode,'REG_DWORD')
			return nil
		rescue::Exception => e
			print_error("Error changing startup mode.  #{e.to_s}")
		end
	end

	def meterpreter_service_create(name, display_name, executable_on_host,mode=2)  #sets
		mode = normalize_mode(mode,true)
		adv = client.railgun.get_dll('advapi32')
		begin
			manag = adv.OpenSCManagerA(nil,nil,0x13)
			if(manag["return"] != 0)
				# SC_MANAGER_CREATE_SERVICE = 0x0002
				newservice = adv.CreateServiceA(manag["return"],name,display_name,
				0x0010,0X00000010,mode,0,executable_on_host,nil,nil,nil,nil,nil)
				adv.CloseServiceHandle(newservice["return"])
				adv.CloseServiceHandle(manag["return"])
				#SERVICE_START=0x0010  SERVICE_WIN32_OWN_PROCESS= 0X00000010
				#SERVICE_AUTO_START = 2 SERVICE_ERROR_IGNORE = 0
				if newservice["GetLastError"] == 0
					return nil
				elsif newservice["GetLastError"] == 1072
					raise Rex::Post::Meterpreter::RequestError.new(__method__,'The specified service has been marked for deletion',newservice["GetLastError"])
				else
					raise Rex::Post::Meterpreter::RequestError.new(__method__,"Error creating service,
					railgun reports:#{newservice.pretty_inspect}",newservice["GetLastError"])
				end
			else
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error creating service: #{e.to_s}")
		end
	end

	def meterpreter_service_start(name)  #sets
		adv = client.railgun.get_dll('advapi32')
		begin
			manag = adv.OpenSCManagerA(nil,nil,1)
			if(manag["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
			#open with  SERVICE_START (0x0010)
			servhandleret = adv.OpenServiceA(manag["return"],name,0x10)
			if(servhandleret["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not open service, Access Denied",servhandleret["GetLastError"])
			end
			retval = adv.StartServiceA(servhandleret["return"],0,nil)
			if retval["GetLastError"] == 0
				return nil
			elsif retval["GetLastError"] == 1056
				raise Rex::Post::Meterpreter::RequestError.new(__method__,'An instance of the service is already running.',retval["GetLastError"])
			elsif retval["GetLastError"] == 1058
				raise Rex::Post::Meterpreter::RequestError.new(__method__,'The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.',retval["GetLastError"])
			else
				raise Rex::Post::Meterpreter::RequestError.new(__method__,'The service cannot be started, because of an unknown error',retval["GetLastError"])
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error starting service:  #{e.to_s}")
		ensure 
			adv.CloseServiceHandle(manag["return"]) unless manag.nil?
			adv.CloseServiceHandle(servhandleret["return"]) unless servhandleret.nil?
		end
	end

	def meterpreter_service_stop(name)  #sets
		adv = client.railgun.get_dll('advapi32')
		begin
			manag = adv.OpenSCManagerA(nil,nil,1)
			if(manag["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
			#open with  SERVICE_STOP (0x0020)
			servhandleret = adv.OpenServiceA(manag["return"],name,0x30)
			if(servhandleret["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not Open Service, Access Denied",servhandleret["GetLastError"])
			end
			retval = adv.ControlService(servhandleret["return"],1,56)
			if retval["GetLastError"] == 0
				return nil
			elsif retval["GetLastError"] == 1062
				raise Rex::Post::Meterpreter::RequestError.new(__method__,'The service has not been started.',retval["GetLastError"])
			elsif retval["GetLastError"] == 1052
				raise Rex::Post::Meterpreter::RequestError.new(__method__,'The requested control is not valid for this service.',retval["GetLastError"])
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error stopping service:  #{e.to_s}")
		ensure 
			adv.CloseServiceHandle(manag["return"]) unless manag.nil?
			adv.CloseServiceHandle(servhandleret["return"]) unless servhandleret.nil?
		end
	end

	def meterpreter_service_delete(name)  #sets
		begin
			basekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
			if registry_enumkeys(basekey).index(name)
				servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
				registry_deletekey(servicekey)
				return nil
			else
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not find #{name} as a registered service.",nil)
			end
		rescue::Exception => e
			print_error("Error deleting service:  #{e.to_s}")
		end
	end

#------------------------------------------------------------------------------
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
	def service_create(name, display_name, executable_on_host,startup=2)
		adv = session.railgun.advapi32
		manag = adv.OpenSCManagerA(nil,nil,0x13)
		if(manag["return"] != 0)
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
	def service_start(name)
		adv = session.railgun.advapi32
		manag = adv.OpenSCManagerA(nil,nil,1)
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
	def service_stop(name)
		adv = session.railgun.advapi32
		manag = adv.OpenSCManagerA(nil,nil,1)
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
	# Delete a service by deleting the key in the registry.
	#
	def service_delete(name)
		begin
			basekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
			if registry_enumkeys(basekey).index(name)
				servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
				registry_deletekey(servicekey)
				return true
			else
				return false
			end
		rescue::Exception => e
			print_error(e)
			return false
		end
	end
#-------------------------------------------------------------------------------

	### Helper methods ###

	#
	# Determines whether the session can use meterpreter services methods
	#
	def session_has_services_depend?
		begin
			return !!(session.sys.registry and session.railgun)
		rescue NoMethodError
			return false
		end
	end

	# Ensures mode is sane, like what sc.exe wants to see, e.g. 2 or "AUTO_START" etc returns "auto"
	# If the second argument it true, integers are returned instead of strings  
	#
	def normalize_mode(mode,i=false)
		mode = mode.to_s # someone could theoretically pass in a 2 instead of "2"
		# accepted boot|system|auto|demand|disabled
		if mode =~ /(0|BOOT)/i
			mode = i ? 0 : 'boot' # mode is 'boot', unless i is true, then it's 0
		elsif mode =~ /(1|SYSTEM)/i
			mode = i ? 1 : 'system'
		elsif mode =~ /(2|AUTO)/i
			mode = i ? 2 : 'auto'
		elsif mode =~ /(3|DEMAND|MANUAL)/i
			mode = i ? 3 : 'demand'
		elsif mode =~ /(4|DISABLED)/i
			mode = i ? 4 : 'disabled'
		end
		return mode		
	end
end

end
end
end
