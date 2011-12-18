require 'msf/core/post/windows/registry'

module Msf
class Post
module Windows

module WindowsServices
	#TODO:  Create a reverse constant lookup for railgun
	# constant_reverse_lookup(dec_or_hex_value,filer_regex=nil)
	# usage: 	lookup(1072) returns "ERROR_SERVICE_MARKED_FOR_DELETE"
	#			lookup(0x04, /SERVICE_/) might return "SERVICE_QUERY_STATUS"

	# these symbols are used for hash keys and are scoped here to allow a consistent api
	CURRENT_SERVICE_STATUS_PROCESS_STRUCT_NAMES = [:type,:state,:controls,:win32_exit_code,
	:service_exit_code,:checkpoint,:wait_hint,:pid,:flags]

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
	# TODO:  Deprecate this in favor os service_query_config and service_query_ex

	def service_info(name,extended_info=false)
		if session_has_services_depend?
			meterpreter_service_info(name)
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
	
	def service_query_config(service_name)
		if session_has_services_depend?
			#TODO:  implement this, check if shell needs a status vs config
			return "not implemented yet"
			meterpreter_service_query_config(service_name)
		else
			shell_service_query_config(service_name)
		end
		
	end

	#
	# Get Windows Service state only. 
	#
	# returns a string with state info such as "4 RUNNING,STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN"
	# could normalize it to just "RUNNING" if desired, but not currently
	# NOTE:  Currently the meterpreter version will only return primary state, like "4 RUNNING"

	def service_query_state(service_name)
		if session_has_services_depend?
			meterpreter_service_query_state(service_name)
		else
			shell_service_query_state(service_name)
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
		running_services = shell_service_list_running
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
		# TODO:  Deprecate this for query_config and query_ex
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
	# TODO:  Convert this to use railgun
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
		state = meterpreter_service_query_state(service_name)
		return true if state =~ /RUNNING/
		# otherwise
		return false
	end
	
	def meterpreter_service_query_state(service_name)
		h = meterpreter_service_query_status(service_name)
		return nil unless h
		# format human-like
		case h[:state]
		when 5
			return "5 CONTINUE_PENDING"
		when 6
			return "6 PAUSE_PENDING"
		when 7
			return "7 PAUSED"
		when 4
			return "4 RUNNING"
		when 2
			return "2 START_PENDING"
		when 3
			return "3 STOP_PENDING"
		when 1
			return "1 STOPPED"
		else
			return "UNKNOWN"
		end
	end
	
	def meterpreter_service_list_running
		all_services = meterpreter_service_list
		run_services = []
		all_services.each do |s|
			run_services << s if meterpreter_service_running?(s)
		end
		return run_services
	end

	# returns hash
	def meterpreter_service_query_status(service_name)
		# use railgun to make the service status query
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
				['DWORD','InfoLevel',		'in'], # SC_STATUS_PROCESS_INFO, always 0
				['PBLOB','lpBuffer',		'out'],
				['DWORD','cbBufSize',		'in'],
				['PDWORD','pcBytesNeeded',	'out']
			])
		end
		# run the railgun query
		begin
			serv_handle,scum_handle = get_serv_handle(service_name,"SERVICE_QUERY_STATUS")
			print_debug "Railgunning queryservicestatusEx"
			railhash = rg.advapi32.QueryServiceStatusEx(serv_handle,0,37,37,4)
			print_debug "Railgun returned:  #{railhash.inspect}"
			if railhash["GetLastError"] == 0
				return parse_service_status_process_structure(results_hash["lpBuffer"])
			else
				raise_windows_error(railhash["GetLastError"],__method__)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			#return nil if e.to_s =~ /Could not Open Service/
			# otherwise print the error
			print_error("Error getting service status:  #{e.to_s}")
			return nil
		ensure
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
		end
	end
		
	def meterpreter_service_info(service_name)
		#TODO:  convert this to railgun or just deprecate for query_config or _status
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
		#TODO convert this to railgun, see service_start and _create etc
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
		rg = session.railgun # can't use get_service_handle as service doesn't exist yet
		begin
			manag = rg.advapi32.OpenSCManagerA(nil,nil,"SC_MANAGER_CREATE_SERVICE")
			if(manag["return"] != 0)
				newservice = rg.advapi32.CreateServiceA(
					manag["return"],
					name,display_name,
					#"SERVICE_ALL_ACCESS", railgun doesn't recognize this
					0xF01FF,
					"SERVICE_WIN32_OWN_PROCESS",
					mode,
					0,
					executable_on_host,
					nil,nil,nil,nil,nil)
				case newservice["GetLastError"]
				when 0 #success
					return nil
				when rg.const("ERROR_SERVICE_MARKED_FOR_DELETE")
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					'The specified service has been marked for deletion',newservice["GetLastError"])
				when rg.const("ERROR_SERVICE_EXISTS")
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					'The specified service already exists',newservice["GetLastError"])
				when rg.const("ERROR_DUPLICATE_SERVICE_NAME")
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					'The specified service name or display name is already in use',
					newservice["GetLastError"])
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
		ensure
			rg.advapi32.CloseServiceHandle(newservice["return"]) if newservice
			rg.advapi32.CloseServiceHandle(manag["return"]) if manag
		end
	end

	def meterpreter_service_start(service_name)
		rg = session.railgun
		begin
			serv_handle,scum_handle = get_serv_handle(service_name,"SERVICE_START")
			# railgun doesn't 'end
			railhash = session.railgun.advapi32.StartServiceA(serv_handle,0,nil)
			if railhash["GetLastError"] == 0
				return nil
			else
				raise_windows_error(railhash["GetLastError"],__method__)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error starting service:  #{e.to_s}")
		ensure 
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end

	def meterpreter_service_stop(service_name)
		#TODO:  create a meterpreter_service_control, and bounce this method to it
		rg = session.railgun
		begin
			serv_handle,scum_handle = get_serv_handle(service_name,"SERVICE_STOP")
			railhash = session.railgun.advapi32.ControlService(serv_handle,"SERVICE_CONTROL_STOP",nil)
			if railhash["GetLastError"] == 0
				return nil
			else
				raise_windows_error(railhash["GetLastError"],__method__)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error stopping service:  #{e.to_s}")
		ensure 
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end

	def meterpreter_service_delete(service_name)
		rg = session.railgun
		begin
			serv_handle,scum_handle = get_serv_handle(service_name,"DELETE")
			railhash = session.railgun.advapi32.DeleteService(serv_handle)
			if railhash["GetLastError"] == 0
				return nil
			else
				raise_windows_error(railhash["GetLastError"],__method__)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error deleting service:  #{e.to_s}")
		ensure 
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end

	### Helper methods ###

	#
	# Determines whether the session can use meterpreter services methods
	#
	def session_has_services_depend?
		begin
			return !!(session.sys.registry and session.railgun)
			##print_debug "using meterpreter version"
		rescue NoMethodError
			##print_debug "using SHELL version"
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
	
	def get_serv_handle(s_name,serv_privs="SERVICE_INTERROGATE",scm_privs="SC_MANAGER_ENUMERATE_SERVICE")
		if not session_has_services_depend?
			raise Error.new "get_serv_handle only valid for meterpreter sessions"
		end
		rg = session.railgun
		begin
			manag = rg.advapi32.OpenSCManagerA(nil,nil,scm_privs)
			if(manag["return"] == 0)
				err = manag["GetLastError"]
				case err
				when rg.const("ERROR_ACCESS_DENIED")
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					'The requested access was denied',err)
				when rg.const("ERROR_DATABASE_DOES_NOT_EXIST")
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					'The specified SCM database does not exist',err)
				else
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					"Unknown error accessing the Service Control Manager, " +
					"railgun reports:#{manag.pretty_inspect}",err)
				end
			end
			servhandleret = rg.advapi32.OpenServiceA(manag["return"],s_name,serv_privs)
			if(servhandleret["return"] == 0)
				err = servhandleret["GetLastError"]
				case err
				when rg.const("ERROR_ACCESS_DENIED")
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					'The requested access was denied',err)
				when rg.const("ERROR_SERVICE_DOES_NOT_EXIST")
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					'The specified service does not exist',err)
				when rg.const("ERROR_INVALID_HANDLE")
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					'The specified handle is invalid',err)
				when rg.const("ERROR_INVALID_NAME")
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					'The specified service name is invalid',err)
				else
					raise Rex::Post::Meterpreter::RequestError.new(__method__,
					"Unknown error accessing the Service Control Manager, " +
					"railgun reports:#{manag.pretty_inspect}",err)
				end
			end
			return servhandleret["return"]
		rescue Rex::Post::Meterpreter::RequestError => e
			#return nil if e.to_s =~ /Could not Open Service/
			# otherwise print the error
			print_error("Error getting service status:  #{e.to_s}")
			return nil
		ensure 
			rg.advapi32.CloseServiceHandle(manag["return"]) if manag
			rg.advapi32.CloseServiceHandle(servhandleret["return"]) if servhandleret
		end
	end
	
	def raise_windows_error(err_val, method_involved)
		#TODO:  use idea of railgun constant_reverse_lookup(err_val)
		# err = constant_reverse_lookup(err_val)
		# if err
		#	raise Rex::Post::Meterpreter::RequestError.new(__method__,
		#			"Windows reported the following error:#{err}",err_val)
		rg = session.railgun
		case err_val
		when the_err = rg.const("ERROR_INVALID_HANDLE")
			raise Rex::Post::Meterpreter::RequestError.new(method_involved,
			"Windows reported:  #{the_err}",err_val)
		else
			raise Rex::Post::Meterpreter::RequestError.new(method_involved,
			"Windows reported an error that I don't feel like handling (#{err_val})",err_val)
		#		"Windows reported an error that railgun doesn't recognize (#{err_val})",err_val)
		end
	end
	
	#
	# Converts a hex string into hash representing a service_status_process_structure
	# with decimal windows constants.  hex_string normally comes from a PBLOB lpBuffer (Railgun)
	#
	def parse_service_status_process_structure(hex_string)
		print_debug "parsing #{hex_string.inspect}"
		names = CURRENT_SERVICE_STATUS_PROCESS_STRUCT_NAMES
		arr_of_arrs = names.zip(hex_string.unpack("V8"))
		hashish = Hash[*arr_of_arrs.flatten]
	end
	
	#typedef struct _SERVICE_STATUS_PROCESS {
	#	DWORD dwServiceType;
	#	DWORD dwCurrentState;
	#	DWORD dwControlsAccepted;
	#	DWORD dwWin32ExitCode;
	#	DWORD dwServiceSpecificExitCode;
	#	DWORD dwCheckPoint;
	#	DWORD dwWaitHint;
	#	DWORD dwProcessId;
	#	DWORD dwServiceFlags;
	#}

	#
	# Converts a hash into human readable service_status_process_structure info
	# as a hash adding human readable commentary.  ssps_hash normally comes
	# from parse_service_status_process_structure
	#
	def beautify_service_status_process_structure(ssps_hash,railgun_instance)
		rg = railgun_instance
		rg.const("SERVICE_QUERY_STATUS") # returns 4
		# TODO:  Is there any easy way to do this?
	end
	
	def parse_and_pretty_service_status_process_structure(hex_string,railgun_instance)
		h = parse_and_pretty_service_status_process_structure(hex_string)
		beautify_service_status_process_structure(h,railgun_instance)
	end
end

end
end
end
