$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

module Lab
module Modifier
module Meterpreter

end
end
end


# This allows us to override the default way of running commands
# Currently useful for the esx controller 

module Lab
class Vm
	
	attr_accessor :framework
	attr_accessor :session
	attr_accessor :session_input
	attr_accessor :session_output


	def create_framework
		return if @framework
		@framework    = Msf::Simple::Framework.create
	end
	
	# perform the setup only once
	def setup_meterpreter
		return if @session

		# require the framework (assumes this sits in lib/lab/modifiers)
		require 'msf/base'

		create_framework

		@session 		= nil
		@session_input        	= Rex::Ui::Text::Input::Buffer.new
		@session_output       	= Rex::Ui::Text::Output::Buffer.new
	
		if @os == "windows"
			exploit_name = 'windows/smb/psexec'
			payload_name = 'windows/meterpreter/bind_tcp'
			options = {	"RHOST"		=> @vmid, 
					"SMBUser" 	=> @vm_user, 
					"SMBPass" 	=> @vm_pass}

			# Initialize the exploit instance
			exploit = @framework.exploits.create(exploit_name)

			begin 
				# Fire it off.
				@session = exploit.exploit_simple(
					'Payload'     	=> payload_name,
					'Options'   	=> options,
					'LocalInput'  	=> @session_input,
					'LocalOutput' 	=> @session_output)
				@session.load_stdapi
			rescue
				raise "Unable to exploit"
			end
							
		else
			module_name = 'scanner/ssh/ssh_login'
			payload_name = 'linux/x86/meterpreter/bind_tcp'
			options = {	"RHOSTS"		=> @vmid, 
					"USERNAME" 		=> @vm_user, 
					"PASSWORD" 		=> @vm_pass, 
					"BLANK_PASSWORDS" 	=> false, 
					"USER_AS_PASS" 		=> false, 
					"VERBOSE" 		=> false}

			# Initialize the module instance
			aux = @framework.auxiliary.create(module_name)
			
			begin 
				# Fire it off.
				aux.run_simple(
					'Payload'     => payload_name,
					'Options'     => options,
					'LocalInput'  => @session_input,
					'LocalOutput' => @session_output)
				
				@session = @framework.sessions.first.last
			rescue
				raise "Unable to exploit"
			end
		end
	end

	def run_command(command, timeout=60)
		setup_meterpreter
		@session.shell_command_token(command, timeout)
	end
	
	
	# This isn't part of the normal API, but too good to pass up. 
	def run_script(script, options)
		if @session.type == "meterpreter"
			@session.execute_script(script, options)
		else
			raise "Unsupported on #{@session.type}"
		end
	end
	
	# For meterpreter API compatibility
	#def execute_file(script,options)
	#	run_script(script,options)
	#end
	
	def copy_to(from,to)
		setup_meterpreter
		if @session.type == "meterpreter"
			@session.run_cmd("upload #{from} #{to}")
		else
			@driver.copy_to(from,to)
		end
	end
	
	def copy_from(from,to)
		setup_meterpreter
		if @session.type == "meterpreter"
			@session.run_cmd("download #{from} #{to}")
		else
			@driver.copy_from(from,to)
		end
	end
	
end
end
