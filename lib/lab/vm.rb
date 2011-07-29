##
## $Id$
##

module Lab
class Vm
	
	attr_accessor :vmid
	attr_accessor :name
	attr_accessor :descripition
	attr_accessor :location
	attr_accessor :driver
	attr_accessor :credentials
	attr_accessor :tools
	attr_accessor :type
	attr_accessor :user
	attr_accessor :host
	attr_accessor :os
	attr_accessor :arch

	## Initialize takes a vm configuration hash of the form
	##  - vmid (unique identifier)
	##    driver (vm technology)
	##    user (if applicable - remote system)
	##    host (if applicable - remote system)
	##    pass (if applicable - remote system)
	##    location (file / uri)
	##    credentials (of the form [ {'user'=>"user",'pass'=>"pass", 'admin' => false}, ... ])
	##    os (currently only linux / windows)
	##    arch (currently only 32 / 64
	
	def initialize(config = {})	

		# Mandatory
		@vmid = config['vmid'] 
		raise "Invalid VMID" unless @vmid

		@driver = nil
		@driver_type = filter_input(config['driver'])
		@driver_type.downcase!

		@name = config['name'] || ""	# not used in command lines
		@description = config['description'] || "" # not used in command lines
		@tools = config['tools'] || false # don't filter this, not used in cmdlines
		@os = config['os'] || nil				
		@arch = config['arch']	|| nil	
		@type = filter_input(config['type']) || "unspecified"
		@credentials = config['credentials'] || []

		# Load in a list of modifiers. These provide additional methods
		# TODO - currently it is up to the user to verify that 
		# modifiers are properly used with the correct VM image. If not, 
		# the results are likely to be disasterous. 		
		@modifiers = config['modifiers']
	
		# Optional for virtualbox
		@location = filter_input(config['location'])

		# Only applicable to remote systems
		@user = filter_input(config['user']) || nil
		@host = filter_input(config['host']) || nil

		# pass might need to be unfiltered, or filtered less
		@pass = filter_input(config['pass']) || nil

		#Only dynagen
		@platform = config['platform']

		# Process the correct driver
		if @driver_type == "workstation"
			@driver = Lab::Drivers::WorkstationDriver.new(@vmid, @location, @os, @tools, @credentials)
		elsif @driver_type == "workstation_vixr"
			@driver = Lab::Drivers::WorkstationVixrDriver.new(@vmid, @location, @os, @tools, @user, @host, @credentials)	
		elsif @driver_type == "remote_workstation"
			@driver = Lab::Drivers::RemoteWorkstationDriver.new(@vmid, @location, @os, @tools, @user, @host, @credentials)	
		elsif @driver_type == "virtualbox"
			@driver = Lab::Drivers::VirtualBoxDriver.new(@vmid, @location, @credentials)
		elsif @driver_type == "dynagen"
			@driver = Lab::Drivers::DynagenDriver.new(@vmid, @location,@platform)	
		elsif @driver_type == "remote_esx"
			@driver = Lab::Drivers::RemoteEsxDriver.new(@vmid, @os, @tools, @user, @host, @credentials)
		#elsif @driver_type == "qemu"
		#	@driver = Lab::Drivers::QemuDriver.new	
		#elsif @driver_type == "qemudo"
		#	@driver = Lab::Drivers::QemudoDriver.new	
		#elsif @driver_type == "fog"
		#	@driver = Lab::Drivers::FogDriver.new	
		else
			raise "Unknown Driver Type"
		end
		
		# Now handle the modifiers - for now, just eval'm
 		@modifiers.each { |modifier|  self.class.send(:include, eval("Lab::Modifier::#{modifier}"))}
		
	end
	
	def running?
		@driver.running?
	end

	def location
		@driver.location
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

	def create_snapshot(snapshot)
		@driver.create_snapshot(snapshot)
	end

	def revert_snapshot(snapshot)
		@driver.revert_snapshot(snapshot)
	end

	def delete_snapshot(snapshot)
		@driver.delete_snapshot(snapshot)
	end

	def revert_and_start(snapshot)
		self.revert_snapshot(snapshot)
		self.start
	end

	def copy_to(from,to)
		@driver.copy_to(from,to)
	end
	
	def copy_from(from,to)
		@driver.copy_from(from,to)
	end
	
	def run_command(command)
		@driver.run_command(command)
	end

	def check_file_exists(file)
		@driver.check_file_exists(file)
	end
	
	def create_directory(directory)
		@driver.create_directory(directory)
	end

	def open_uri(uri)
		# we don't filter the uri, as it's getting tossed into a script 
		# by the driver
		if @os == "windows"
			command = "\"C:\\program files\\internet explorer\\iexplore.exe\" #{uri}"
		else
			command = "firefox #{uri}"
		end

		@driver.run_command(command)
	end

	def to_s
		return "#{@vmid}: #{@location}"
	end

	def to_yaml
		out =  " - vmid: #{@vmid}\n"
		out += "   driver: #{@driver_type}\n"
		out += "   location: #{@driver.location}\n"
		out += "   type: #{@type}\n"
		out += "   tools: #{@tools}\n"
		out += "   os: #{@os}\n"
		out += "   arch: #{@arch}\n"
		if @user or @host # Remote vm/drivers only
			out += "   user: #{@user}\n"
			out += "   host: #{@host}\n"
		end

		out += "   credentials:\n"
		@credentials.each do |credential|		
			out += "     - user: #{credential['user']}\n"
			out += "       pass: #{credential['pass']}\n"
		end
		
	 	return out
	end
private

	def filter_input(string)
		return unless string
					
		if !(string =~ /^[(!)\d*\w*\s*\[\]\{\}\/\\\.\-\"\(\)]*$/)
			raise "WARNING! Invalid character in: #{string}"
		end

		string
	end
end
end
