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
require 'msf/ui/gtk2/bidirectional_pipe'

module Msf
module Ui
module Gtk2

###
#
# This class implements a user interface driver on a gtk2 interface.
#
###
class Driver < Msf::Ui::Driver
	
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

		# Initialize configuration
		Msf::Config.init
		
		# Initialize logging
		initialize_logging

		# Initialize attributes
		self.framework = Msf::Simple::Framework.create
		
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
