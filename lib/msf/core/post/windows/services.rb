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
			meterpreter_service_list_running
		else
			shell_service_list_running
		end
	end
	
	#
	# Returns true if the given service is running
	#
	def service_running?(service_name)
		if session_has_services_depend?
			meterpreter_service_running?(service_name)
		else
			shell_service_running?(service_name)
		end
	end

	#
	# Get Windows Service information. 
	#
	# Information returned in a hash with display name, startup mode and
	# command executed by the service. Service name is case sensitive.  Hash
	# keys are Name, Start, Command and Credentials.
	#

	def service_info(name,extended_info=false)
		if session_has_services_depend?
			meterpreter_service_info(name,extended_info)
		else
			shell_service_info(name, extended_info)
		end
	end
	
	def service_info_advanced(name,extended_info=false)
		if session_has_services_depend?
			meterpreter_service_info_advanced(name,extended_info)
		else
			shell_service_info(name, extended_info)
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
	# Non-native Meterpreter windows service manipulation methods, i.e. shell or java meterp etc
	##
	def shell_service_list
		services = []
		begin
			cmd = "cmd.exe /c sc query type= service state= all"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SERVICE_NAME:/
				results.each_line do |line| 
					if line =~ /SERVICE_NAME:/
						h = win_parse_results(line)
						services << h[:service_name]
					end 
				end
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return nil
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
		return services
	end

	def shell_service_list_running
		#SERVICE_NAME: Winmgmt
		#DISPLAY_NAME: Windows Management Instrumentation
      	# <...etc...>
		#
		services = []
		begin
			cmd = "cmd.exe /c sc query type= service"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SERVICE_NAME:/
				results.each_line do |line| 
					if line =~ /SERVICE_NAME:/
						h = win_parse_results(line)
						services << h[:service_name]
					end 
				end
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return nil
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
		return services
	end

	def shell_service_running?(service_name)
		running_services = self.shell_service_list_running
		return true if running_services.include?(service_name)
	end
	
	def shell_service_query_config(name)
		service = {}
		begin
			cmd = "cmd.exe /c sc qc #{name.chomp}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				#[SC] QueryServiceConfig SUCCESS
				#
				#SERVICE_NAME: winmgmt
				#      TYPE          : 20  WIN32_SHARE_PROCESS
				#      START_TYPE      : 2  AUTO_START
				#      ERROR_CONTROL    : 0  IGNORE
				#      BINARY_PATH_NAME  : C:\Windows\system32\svchost.exe -k netsvcs
				#      <...>
				#      DISPLAY_NAME     : Windows Management Instrumentation
				#      DEPENDENCIES     : RPCSS
				#      		   : OTHER
				#      SERVICE_START_NAME : LocalSystem
				# 
				service = win_parse_results(results)
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return nil
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
		return service
	end
	
	def shell_service_info(name,extended_info=false)
		service = {}
		begin
			h = shell_service_query_config(name)
			return nil unless h
			if ! extended_info
				# this is here only for backwards compatibility with the original meterp version
				service['Name'] = h[:service_name]
				service['Startup'] = normalize_mode(h[:start_type])
				service['Command'] = h[:binary_path_name]
				service['Credentials'] = h[:service_start_name]
				return service
			else
				# this is alot more useful stuff, but not backward compatible
				return h
			end
		rescue Exception => e
			print_error(e.to_s)
			return nil
		end
		return nil
	end

	def shell_service_query_ex(name)
		service = {}
		begin
			cmd = "cmd.exe /c sc queryex #{name.chomp}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SERVICE_NAME/ # NOTE: you can't use /SUCCESS/ here
				#SERVICE_NAME: winmgmt
				#      TYPE          : 20  WIN32_SHARE_PROCESS
				#      STATE          : 4  RUNNING
				#                      (STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN)
				#      WIN32_EXIT_CODE   : 0  (0x0)
				#      SERVICE_EXIT_CODE  : 0  (0x0)
				#      CHECKPOINT      : 0x0
				#      WAIT_HINT       : 0x0
				#      PID           : 1088
				#      FLAGS          :
				# 
				service = win_parse_results(results)
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return nil
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
		return service
	end
	
	def shell_service_query_state(name)
		begin
			h = service_query_ex(name)
			return h[:state] if h # return the state
		rescue Exception => e
			print_error(e.to_s)
		end
		return nil
	end

	def shell_service_change_startup(name,mode)
		begin
			mode = normalize_mode(mode)
			cmd = "cmd.exe /c sc config #{name} start= #{mode}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error changing startup mode #{name} to #{mode}:  #{eh[:error]}",
					eh[:errval],cmd) 
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_service_create(name,display_name="Server Service",executable_on_host="",mode="auto")
		#  sc create [service name] [binPath= ] <option1> <option2>...
		begin
			mode = normalize_mode(mode)
			cmd = "cmd.exe /c sc create #{name} binPath= \"#{executable_on_host}\" " +
				"start= #{mode} DisplayName= \"#{display_name}\""
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error creating service #{name}:  #{eh[:error]}",eh[:errval],cmd)
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_service_start(name)
		begin
			cmd = "cmd.exe /c sc start #{name}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /(SUCCESS|START_PENDING|RUNNING)/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error starting #{name}:  #{eh[:error]}",eh[:errval],cmd)
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_service_stop(name)
		begin
			cmd = "cmd.exe /c sc stop #{name}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS|STOP_PENDING|STOPPED|/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error stopping service #{name}:  #{eh[:error]}",eh[:errval],cmd)
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_service_delete(name)
		begin
			cmd = "cmd.exe /c sc delete #{name}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Error deleting service #{name}:  #{eh[:error]}",eh[:errval],cmd)
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end
	

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
			#a.join?
			a.join
		rescue Exception => e
			print_error("Error enumerating services.  #{e.to_s}")
		end
		return services
	end
	
	def meterpreter_service_running?(service_name)
		rg = session.railgun
		rg.add_dll('advapi32') unless rg.get_dll('advapi32') # load dll if not loaded
		# define the function if not defined
		if ! rg.advapi32.functions['QueryServiceStatus']
			# MSDN
			#BOOL WINAPI QueryServiceStatusEx(
			#	__in   SC_HANDLE hService,
			#	__out  LPSERVICE_STATUS lpServiceStatus
			#);
			rg.add_function('advapi32', 'QueryServiceStatusEx', 'BOOL',[
				['DWORD','hService',		'in'],
				['PBLOB','lpServiceStatus',	'out']
			])
		end
		begin
			manag = rg.advapi32.OpenSCManagerA(nil,nil,1)
			if(manag["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
			#open with  SERVICE_QUERY_STATUS (0x0004) privs
			servhandleret = rg.advapi32.OpenServiceA(manag["return"],service_name,0x04)
			if(servhandleret["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				"Could not Open Service, Access Denied",servhandleret["GetLastError"])
			end
			ret = rg.advapi32.QueryServiceStatus(servhandleret["return"],4+1)
			return true if ret['lpServiceStatus'].unpack("H*").first =~ /00000004/
			# otherwise
			return false
		rescue Rex::Post::Meterpreter::RequestError => e
			return false if e.to_s =~ /Could not Open Service/
			# otherwise print the error
			print_error("Error getting service status:  #{e.to_s}")
			return false
		ensure 
			rg.advapi32.CloseServiceHandle(manag["return"]) unless manag.nil?
			rg.advapi32.CloseServiceHandle(servhandleret["return"]) unless servhandleret.nil?
		end
	
		# advanced version below, in work
			#info = meterpreter_service_info_advanced(service_name, true)
			# if dwCurrentState is 0x00000004 then SERVICE_RUNNING
			#return true if ret['lpServiceStatus'].unpack("H8").first =~ /00000004/
			# otherwise
			#return false
	end
	
	def meterpreter_service_list_running
		all_services = self.meterpreter_service_list
		run_services = []
		all_services.each do |s|
			run_services << s if meterpreter_service_running?(s)
		end
		return run_services
	end

	def meterpreter_service_info_advanced(service_name, extended_info)
		rg = session.railgun
		rg.add_dll('advapi32') unless rg.get_dll('advapi32') # load dll if not loaded
		# define the function if not defined
		if ! rg.advapi32.functions['QueryServiceStatusEx']
			# MSDN
			#BOOL WINAPI QueryServiceStatusEx(
			#	__in       SC_HANDLE hService,
			#	__in       SC_STATUS_TYPE InfoLevel,
			#	__out_opt  LPBYTE lpBuffer,
			#	__in       DWORD cbBufSize,
			#	__out      LPDWORD pcbBytesNeeded
			#);
			rg.add_function('advapi32', 'QueryServiceStatusEx', 'BOOL',[
				['DWORD','hService',		'in'],
				['DWORD','InfoLevel',		'in'], # SC_STATUS_PROCESS_INFO, always 0 basically
				['PBLOB','lpBuffer',		'out'],
				['DWORD','cbBufSize',		'in'],
				['PDWORD','pcBytesNeeded',	'out']
			])
		end
		
		begin
			manag = rg.advapi32.OpenSCManagerA(nil,nil,1)
			if(manag["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
			#open with  SERVICE_QUERY_STATUS (0x0004) privs
			servhandleret = rg.advapi32.OpenServiceA(manag["return"],service_name,0x04)
			if(servhandleret["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				"Could not Open Service, Access Denied",servhandleret["GetLastError"])
			end
			ret = rg.advapi32.QueryServiceStatusEx(servhandleret["return"],0,9*4+1,9*4+1,4)
			print_good ret["lpBuffer"].unpack("H4")

		rescue Rex::Post::Meterpreter::RequestError => e
			return false if e.to_s =~ /Could not Open Service/
			# otherwise print the error
			print_error("Error getting service status:  #{e.to_s}")
			return false
		ensure 
			rg.advapi32.CloseServiceHandle(manag["return"]) unless manag.nil?
			rg.advapi32.CloseServiceHandle(servhandleret["return"]) unless servhandleret.nil?
		end
	end
	
	def meterpreter_service_info(service_name)
		service = {}
		servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{service_name.chomp}"
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

	def meterpreter_service_create(name, display_name, executable_on_host,mode=2)
		mode = normalize_mode(mode,true)
		adv = client.railgun.get_dll('advapi32')
		begin
			manag = adv.call_function OpenSCManagerA(nil,nil,0x13)
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
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					'The specified service has been marked for deletion',newservice["GetLastError"])
				else
					raise Rex::Post::Meterpreter::RequestError.new(__method__,"Error creating service,
					railgun reports:#{newservice.pretty_inspect}",newservice["GetLastError"])
				end
			else
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error creating service: #{e.to_s}")
		end
	end

	def meterpreter_service_start(name)
		adv = client.railgun.get_dll('advapi32')
		begin
			manag = adv.OpenSCManagerA(nil,nil,1)
			if(manag["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
			#open with  SERVICE_START (0x0010)
			servhandleret = adv.OpenServiceA(manag["return"],name,0x10)
			if(servhandleret["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				"Could not open service, Access Denied",servhandleret["GetLastError"])
			end
			retval = adv.StartServiceA(servhandleret["return"],0,nil)
			if retval["GetLastError"] == 0
				return nil
			elsif retval["GetLastError"] == 1056
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				'An instance of the service is already running.',retval["GetLastError"])
			elsif retval["GetLastError"] == 1058
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				'The service cannot be started, either because it is disabled or because 
				it has no enabled devices associated with it.',retval["GetLastError"])
			else
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				'The service cannot be started, because of an unknown error',retval["GetLastError"])
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error starting service:  #{e.to_s}")
		ensure 
			adv.CloseServiceHandle(manag["return"]) unless manag.nil?
			adv.CloseServiceHandle(servhandleret["return"]) unless servhandleret.nil?
		end
	end

	def meterpreter_service_stop(name)
		adv = client.railgun.get_dll('advapi32')
		begin
			manag = adv.OpenSCManagerA(nil,nil,1)
			if(manag["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
			#open with  SERVICE_STOP (0x0020)
			servhandleret = adv.OpenServiceA(manag["return"],name,0x30)
			if(servhandleret["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				"Could not Open Service, Access Denied",servhandleret["GetLastError"])
			end
			retval = adv.ControlService(servhandleret["return"],1,56)
			if retval["GetLastError"] == 0
				return nil
			elsif retval["GetLastError"] == 1062
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				'The service has not been started.',retval["GetLastError"])
			elsif retval["GetLastError"] == 1052
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				'The requested control is not valid for this service.',retval["GetLastError"])
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error stopping service:  #{e.to_s}")
		ensure 
			adv.CloseServiceHandle(manag["return"]) unless manag.nil?
			adv.CloseServiceHandle(servhandleret["return"]) unless servhandleret.nil?
		end
	end

	def meterpreter_service_delete(name)
		begin
			basekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
			if registry_enumkeys(basekey).index(name)
				servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
				registry_deletekey(servicekey)
				return nil
			else
				raise Rex::Post::Meterpreter::RequestError.new(__method__,
				"Could not find #{name} as a registered service.",nil)
			end
		rescue::Exception => e
			print_error("Error deleting service:  #{e.to_s}")
		end
	end

	### Helper methods ###

	#
	# Determines whether the session can use meterpreter services methods
	#
	def session_has_services_depend?
		begin
			return !!(session.sys.registry and session.railgun)
			#print_good "using meterpreter version"
		rescue NoMethodError
			#print_good "using SHELL version"
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
