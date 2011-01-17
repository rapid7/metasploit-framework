##
## $Id$
##

require 'workstation_driver'
require 'remote_workstation_driver'
#require 'server_driver'
#require 'qemu_driver'
#require 'virtualbox_driver'
#require 'ec2_driver'
#require 'azure_driver'

module Lab

class Vm
	
	attr_accessor :vmid
	attr_accessor :driver
	attr_accessor :location
	attr_accessor :credentials
	attr_accessor :tools

	## Initialize takes a vm configuration hash of the form
	##  - vmid (unique identifier)
	##    driver (vm technology)
	##    user (if applicable)
	##    host (if applicable)
	##    location (file / uri)
	##    credentials (of the form [ {'user'=>"user",'pass'=>"pass", 'admin' => false}, ... ])
	def initialize(config = {})	
		@driver = nil
		driver_type = config['driver']
		driver_type.downcase!

		@vmid = config['vmid']
		@location = config['location']

		## Internals
		@credentials = config['credentials'] || []
		@tools = config['tools'] || false		## TODO
		@operating_system = nil				## TODO
		@ports = nil					## TODO
		@vulns = nil					## TODO

		@user = config['user'] || nil
		@host = config['host'] || nil

		if driver_type == "workstation"
			@driver = Lab::Drivers::WorkstationDriver.new(@location, @credentials)
		elsif driver_type == "remote_workstation"
			@driver = Lab::Drivers::RemoteWorkstationDriver.new(@location,@user, @host, @credentials)	
		#elsif driver_type == "server"
		#	@driver = ServerDriver.new
		#elsif driver_type == "virtualbox"
		#	@driver = VirtualBoxDriver.new	
		#elsif driver_type == "qemu"
		#	@driver = QemuDriver.new	
		#elsif driver_type == "ec2"
		#	@driver = Ec2Driver.new	
		#elsif driver_type == "azure"
		#	@driver = AzureDriver.new	
		else
			raise Exception, "Unknown Driver Type"
		end
	end

	
	def running?
		@driver.running?
	end

	def start
		@driver.start
	end

	def stop
		@driver.stop
	end

	def pause
		@driver.pause
	end

	def suspend
		@driver.suspend
	end
	
	def reset
		@driver.reset
	end
	
	def resume
		@driver.resume
	end

	def snapshot(name)
		@driver.snapshot(name)
	end

	## revert needs to restore the current state of the machine
	##   meaning, if it's running when revert is called
	##   we'll want to restart it after reverting it. 
	def revert(name)
		start = false
		if running?
			start = true
		end

		@driver.revert(name)

		if start
			@driver.start
		end
	end

	def copy_to(from_file,to_file)
		raise Exception, "not implemented"
	end
	
	def copy_from(from_file,to_file)
		raise Exception, "not implemented"
	end
	
	def run_command(command,arguments=nil)
		raise Exception, "not implemented"
	end

	def open_uri(uri)
		raise Exception, "not implemented"
	end

	def to_s
		return @vmid.to_s + ": " + @location.to_s
	end

	def to_yaml
		out =  " - vmid: #{@vmid}\n"
		out += "   driver: #{@driver.type}\n"
		out += "   location: #{@location}\n"
		out += "   tools: #{@tools}\n"
		out += "   credentials:\n"
		@credentials.each do |credential|		
			out += "     - user: #{credential['user']}\n"
			out += "       pass: #{credential['pass']}\n"
			out += "       admin: #{credential['admin']}\n"
		end
		
		if @server_user or @server_host
			out += "   server_user: #{@server_user}\n"
			out += "   server_host: #{@server_host}\n"
		end

	 	return out
	end		
end

end
