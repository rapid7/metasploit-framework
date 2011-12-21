require 'msf/core/post/windows/registry'  # TODO:  Remove this dependency

module Msf
class Post
module Windows

module WindowsServices

	# these symbols are used for hash keys and are scoped here to allow a consistent api
	CURRENT_SERVICE_STATUS_PROCESS_STRUCT_NAMES = [:type,:state,:controls,:win32_exit_code,
	:service_exit_code,:checkpoint,:wait_hint,:pid,:flags]

	include Msf::Post::Windows::CliParse
	include ::Msf::Post::Windows::Registry # TODO:  Remove this dependency
	
	#
	# List all Windows Services present. Returns an Array containing the names (keynames)
	# of the services, whether they are running or not.
	#

	def service_list
		if session_has_services_depend?
			#TODO:  remove _new when done
			meterpreter_service_list_new
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
	# Get Windows Service status information. 
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
	
	def service_query_status(service_name)
		if session_has_services_depend?
			meterpreter_service_query_status(service_name)
		else
			#TODO:  implement this, check if shell needs a status vs config
			return "not implemented yet"
			shell_service_query_status(service_name)
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
	def meterpreter_service_list_new (state=0x03)
		# other choices for state: 
		# "SERVICE_STATE_ALL" = 0x03
		# "SERVICE_STATE_ACTIVE" = 0x01
		# "SERVICE_STATE_INACTIVE" = 0x02
		#TODO:  Railgun doesn't seem to know the above constants
		
		# use railgun to make the service query
		rg = session.railgun
		# define the function if not defined
		if not rg.advapi32.functions['EnumServicesStatusA']
			# MSDN
			#BOOL WINAPI EnumServicesStatus(
			#	__in 		 SC_HANDLE hSCManager,
			#	__in         DWORD dwServiceType,
			#	__in         DWORD dwServiceState,
			#	__out_opt    LPENUM_SERVICE_STATUS lpServices,
			#	__in         DWORD cbBufSize,
			#	__out        LPDWORD pcbBytesNeeded,
			#	__out        LPDWORD lpServicesReturned,
			#	__inout_opt  LPDWORD lpResumeHandle
			#);
			rg.add_function('advapi32', 'EnumServicesStatusA', 'BOOL',[
				['DWORD','hSCManager',		'in'],
				['DWORD','dwServiceType',	'in'], #SERVICE_WIN32
				['DWORD','dwServiceState',	'in'], #1, 2, or 3
				['PBLOB','lpServices',		'out'],
				['DWORD','cbBufSize',		'in'],
				['PDWORD','pcBytesNeeded',	'out'],
				['PDWORD','lpServicesReturned','out'], # the number of svs returned
				['PDWORD','lpResumeHandle','inout'] # 0
			])
		end
		#print_debug rg.advapi32.functions.to_s
		# run the railgun query
		begin
			nil_handle,scum_handle = get_serv_handle(0,"SERVICE_QUERY_STATUS")
			# ok, let's use the winapi to figure out just how big our buffer needs to be
			# note, there could be a "race" condition where the buffer size increases after we query
			# but this is about as good as we can do
			print_debug "Running EnumServicesStatus to get buf_size"
			# TODO:  Railgun doesn't know:  SERVICE_WIN32 = 0x30
			# check if it knows SERVICE_WIN32_OWN_PROCESS = 0x10
			railhash = rg.advapi32.EnumServicesStatusA(scum_handle,0x10,state,4,0,4,4,4)
			# passing in a buf size of 0 gives us the required buf size in pcBytesNeeded
			if not railhash["GetLastError"] == 0 #change this to if == 0xEA going forward
				#then this is good, this puts buf size in pcBytesNeeded
				buf_size = railhash["pcBytesNeeded"].to_i
				print_debug "Buffer size:  " + buf_size.to_s
			else # if no error, bad things
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Problem getting buffer size")
			end
			# now use that buf_size to make the real query
			# TODO:  railgun doesn't seem to know "SERVICE_WIN32" which is 0x30
			print_debug "Running EnumServicesStatus with buf_size of #{buf_size}"
			railhash = rg.advapi32.EnumServicesStatusA(scum_handle,0x10,state,buf_size,buf_size,4,4,4)
			# assume for now that each process_struct is buf_size / lpServicesReturned or ?36(37)B
			# for now, let's just see this buffer boyyyyyy
			if railhash["GetLastError"] == 0
				#print_debug "Buffer:  " + railhash["lpServices"].inspect
				print_debug "Number of services:  " + railhash["lpServicesReturned"].to_s
				return railhash["lpServices"].inspect
				#return parse_service_status_process_structure(railhash["lpBuffer"])
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error querying service status",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_INSUFFICIENT_|ERROR_SHUTDOWN_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
			return nil
		ensure
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end
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
			#print_debug "Railgunning queryservicestatusEx"
			railhash = rg.advapi32.QueryServiceStatusEx(serv_handle,0,37,37,4)
			#print_debug "Railgun returned:  #{railhash.inspect}"
			if railhash["GetLastError"] == 0
				return parse_service_status_process_structure(railhash["lpBuffer"])
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error querying service status",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_INSUFFICIENT_|ERROR_SHUTDOWN_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
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
		nil_handle,scum_handle = get_serv_handle(0,nil,"SC_MANAGER_CREATE_SERVICE")
		begin
			new_service = rg.advapi32.CreateServiceA(
				scum_handle,
				name,
				display_name,
				#"SERVICE_ALL_ACCESS", railgun doesn't recognize this
				0xF01FF,
				"SERVICE_WIN32_OWN_PROCESS",
				mode,
				0,
				executable_on_host,
				nil,nil,nil,nil,nil)
			err = new_service["GetLastError"]
			case err
			when 0 #success
				return nil
			else
				handle_railgun_error(err,__method__,"Error starting service",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_CIRCULAR_|ERROR_SERVICE_|ERROR_DUPLICATE_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
		ensure
			rg.advapi32.CloseServiceHandle(new_service["return"]) if new_service
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end

	def meterpreter_service_start(service_name)
		rg = session.railgun
		begin
			serv_handle,scum_handle = get_serv_handle(service_name,"SERVICE_START")
			# railgun doesn't 'end
			railhash = rg.advapi32.StartServiceA(serv_handle,0,nil)
			if railhash["GetLastError"] == 0
				return nil
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error starting service",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_PATH_|ERROR_SERVICE_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
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
			railhash = rg.advapi32.ControlService(serv_handle,"SERVICE_CONTROL_STOP",4)
			if railhash["GetLastError"] == 0
				return nil
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error stopping service",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_DEPENDENT_|ERROR_SHUTDOWN_|ERROR_SERVICE_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
		ensure 
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end

	def meterpreter_service_delete(service_name)
		rg = session.railgun
		begin
			serv_handle,scum_handle = get_serv_handle(service_name,"DELETE")
			railhash = rg.advapi32.DeleteService(serv_handle)
			if railhash["GetLastError"] == 0
				return nil
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error deleting service",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_SERVICE_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
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
	
	def handle_railgun_error(error_code, blame_method, message, railgun_instance, filter_regex=nil)
		err_name_array = railgun_instance.error_lookup(error_code,filter_regex)
		if not err_name_array.nil? and not err_name_array.empty?
			error_name = err_name_array.first
		else
			error_name = nil
		end
    	raise Rex::Post::Meterpreter::RequestError.new(blame_method,
    	"#{message}, Windows returned the following error:  #{error_name}(#{error_code})",error_code)
	end
	
	def get_serv_handle(s_name,serv_privs="SERVICE_INTERROGATE",scm_privs="SC_MANAGER_ENUMERATE_SERVICE")
		# s_name is normally a string, but if s_name is the value 0 then
		# a serv_handle will not be attempted, essentially only a scum_handle will be returned
		if not session_has_services_depend?
			raise Error.new "get_serv_handle only valid for meterpreter sessions"
		end
		rg = session.railgun
		begin
			# get the SCManager handle
			manag = rg.advapi32.OpenSCManagerA(nil,nil,scm_privs)
			scum_handle = manag["return"]
			err = manag["GetLastError"]
			if scum_handle == 0 #then OpenSCManagerA had a problem
				handle_railgun_error(err,__method__,"Error opening the SCManager",rg)
			else # move on to getting the service handle if requested
				return nil,scum_handle if s_name == 0 # only a scum_handle is requested
				servhandleret = rg.advapi32.OpenServiceA(scum_handle,s_name,serv_privs)
				serv_handle = servhandleret["return"]
				
				if(serv_handle == 0) # then OpenServiceA had a problem
					err = servhandleret["GetLastError"]
					handle_railgun_error(err, __method__,"Error opening service handle", rg,
					/^[ERROR_ACCESS_|ERROR_SERVICE_|ERROR_INVALID]/) #limit our error lookups
				end
				#print_debug "Returning:  #{serv_handle.to_s}, #{scum_handle.to_s}"
				return serv_handle,scum_handle
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
			return nil
		# we don't use ensure here cuz we don't want the handles to get closed if no error
		end
	end
	
	#
	# Converts a hex string into hash representing a service_status_process_structure
	# with decimal windows constants.  hex_string normally comes from a PBLOB lpBuffer (Railgun)
	#
	def parse_service_status_process_structure(hex_string)
		#print_debug "parsing #{hex_string.inspect}"
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
