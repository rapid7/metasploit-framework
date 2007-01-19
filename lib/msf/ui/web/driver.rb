require 'rex/proto/http'
require 'msf/core'
require 'msf/base'
require 'msf/ui'

module Msf
module Ui
module Web

require 'msf/ui/web/comm'

###
#
# This class implements a console instance for use by the web interface
#
###

class WebConsole
	attr_accessor :pipe
	attr_accessor :console
	attr_accessor :console_id
	attr_accessor :last_access
	attr_accessor :framework


	class WebConsolePipe < Rex::IO::BidirectionalPipe

		attr_accessor :input
		attr_accessor :output
		attr_accessor :prompt
		attr_accessor :killed

		def eof?
			self.pipe_input.eof?
		end

		def intrinsic_shell?
			true
		end

		def supports_readline
			false
		end
		
		def _print_prompt
		end
		
		def pgets
			self.pipe_input.gets
		end
	end
	

	def initialize(framework, console_id)
		# Configure the framework
		self.framework = framework

		# Configure the ID
		self.console_id = console_id

		# Create a new pipe 
		self.pipe = WebConsolePipe.new
		self.pipe.input = self.pipe.pipe_input

		# Create a read subscriber
		self.pipe.create_subscriber('msfweb')

		# Initialize the console with our pipe
		self.console = Msf::Ui::Console::Driver.new(
			'msf>',
			'>',
			{
				'Framework'   => self.framework,
				'LocalInput'  => self.pipe, 
				'LocalOutput' => self.pipe,
			}
		)
		
		Thread.new { self.console.run }

		update_access()
	end

	def update_access
		self.last_access = Time.now
	end

	def read
		update_access
		self.pipe.read_subscriber('msfweb')
	end

	def write(buf)
		update_access
		self.pipe.write_input(buf)
	end
	
	def shutdown
		self.pipe.killed = true
		self.pipe.close
	end
end
	
###
#
# This class implements a user interface driver on a web interface.
#
###
class Driver < Msf::Ui::Driver


	attr_accessor :framework # :nodoc:
	attr_accessor :consoles # :nodoc:
	attr_accessor :last_console # :nodoc: 

	ConfigCore  = "framework/core"
	ConfigGroup = "framework/ui/web"

	#
	# Initializes a web driver instance and prepares it for listening to HTTP
	# requests.  The constructor takes a hash of options that can control how
	# the web server will operate.
	#
	def initialize(opts = {})
		# Call the parent
		super()

		# Set the passed options hash for referencing later on.
		self.opts = opts

		# Initalize the consoles set
		self.consoles = {}

		# Initialize configuration
		Msf::Config.init
		
		# Initialize logging
		initialize_logging

		# Initialize attributes
		self.framework = Msf::Simple::Framework.create
		
		# Initialize the console count
		self.last_console = 0

		# Give the comm an opportunity to set up so that it can receive
		# notifications about session creation and so on.		
		Comm.setup(framework)
	end

	def create_console
		# Destroy any unused consoles
		clean_consoles
	
		console = WebConsole.new(self.framework, self.last_console)
		self.last_console += 1
		self.consoles[console.console_id.to_s] = console	
		console.console_id.to_s
	end
	
	def write_console(id, buf)
		self.consoles[id] ? self.consoles.write(buf) : nil
	end
	
	def read_console(id)
		self.consoles[id] ? self.consoles.read() : nil
	end
	
	def clean_consoles(timeout=300)
		self.consoles.each_pair do |id, con|
			if (con.last_access + timeout < Time.now)
				con.shutdown
				self.consoles.delete(id)
			end
		end
	end
	
	#
	# Stub
	#
	def run
		true
	end

protected

	attr_accessor :opts      # :nodoc:

	#
	# Initializes logging for the web interface
	#
	def initialize_logging
		level = (opts['LogLevel'] || 0).to_i

		Msf::Logging.enable_log_source(LogSource, level)
	end

end

end
end
end
