require 'msf/core'
require 'msf/base'
require 'msf/ui'

require 'msf/ui/gtk2/controls'
require 'msf/ui/gtk2/app'
require 'msf/ui/gtk2/about'
require 'msf/ui/gtk2/frame'
require 'msf/ui/gtk2/dialogs'
require 'msf/ui/gtk2/logs'
require 'msf/ui/gtk2/stream'
require 'msf/ui/gtk2/view'

module Msf
module Ui
module Gtk2

require 'rex/io/bidirectional_pipe'

###
#
# This class implements a console instance for use by the Gtk2 interface
#
###

class GtkConsole
	attr_accessor :pipe
	attr_accessor :console
	attr_accessor :console_id
	attr_accessor :last_access
	attr_accessor :framework
	attr_accessor :thread

	class GtkConsolePipe < Rex::IO::BidirectionalPipe

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
		self.pipe = GtkConsolePipe.new
		self.pipe.input = self.pipe.pipe_input

		# Create a read subscriber
		self.pipe.create_subscriber('msfweb')

		# Initialize the console with our pipe
		self.console = Msf::Ui::Console::Driver.new(
			'msf',
			'>',
			{
				'Framework'   => self.framework,
				'LocalInput'  => self.pipe, 
				'LocalOutput' => self.pipe,
				'AllowCommandPassthru' => false,
			}
		)
		
		self.thread = Thread.new { self.console.run }
		
		update_access()
	end

	def update_access
		self.last_access = Time.now
	end

	def read
		update_access

		self.pipe.read_subscriber('msfgui')
	end

	def write(buf)
		update_access
		self.pipe.write_input(buf)
	end
	
	def execute(cmd)
		self.console.run_single(cmd)
		self.read
	end
	
	def prompt
		self.pipe.prompt
	end
	
	def tab_complete(cmd)
		self.console.tab_complete(cmd)
	end
	
	def shutdown
		self.pipe.killed = true
		self.pipe.close
		self.thread.kill
	end
end

###
#
# This class implements a user interface driver on a gtk2 interface.
#
###
class Driver < Msf::Ui::Driver
	
	attr_accessor :framework # :nodoc:
	attr_accessor :consoles # :nodoc:
	attr_accessor :last_console # :nodoc: 

	ConfigCore  = "framework/core"
	ConfigGroup = "framework/ui/gtk2"

	#
	# The default resource directory for msfgui
	#
	DefaultResourceDirectory = Msf::Config.data_directory + File::SEPARATOR + "msfgui"

	#
	# Initializes a gtk2 driver instance
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
		
		# Create the gtk2driver global
		$gtk2driver = self
		
		# Init GTK2
		Gtk.init
		
		# Initialize the Gtk2 application object
		@gtk2app = Msf::Ui::Gtk2::MyApp.new()
	end

	#
	# Starts the main gtk2 loop
	#
	def run
		ilog("msfgui has been started", LogSource)
		Gtk.main
		true
	end

	def create_console
		# Destroy any unused consoles
		clean_consoles
	
		console = GtkConsole.new(self.framework, self.last_console)
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
	# Returns the local directory that will hold the files to be serviced.
	#
	def resource_directory
		opts['ResourceDirectory'] || DefaultResourceDirectory
	end
	
	#
	# Returns a new Wx::Icon object
	#
	def get_icon(name)
		Gdk::Pixbuf.new(File.join(resource_directory, 'pix', name))
	end
	
	def render_icon(pix, style, text)
		test = Gtk::Window.new
		#puts test
		return test.render_icon(pix, style, text)
	end

	#
	# The framework instance associated with this driver.
	#
	attr_reader   :framework

protected

	attr_writer   :framework # :nodoc:
	attr_accessor :opts      # :nodoc:

	#
	# Initializes logging for the Gtk2 driver.
	#
	def initialize_logging
		level = (opts['LogLevel'] || 0).to_i

		Msf::Logging.enable_log_source(LogSource, level)
	end

end

end
end
end
