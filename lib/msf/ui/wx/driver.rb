require 'msf/core'
require 'msf/base'
require 'msf/ui'

require 'msf/ui/wx/constants'
require 'msf/ui/wx/controls'
require 'msf/ui/wx/frame'
require 'msf/ui/wx/app'

module Msf
module Ui
module Wx


###
#
# This class implements a user interface driver on a wx graphical interface.
#
###
class Driver < Msf::Ui::Driver

	ConfigCore  = "framework/core"
	ConfigGroup = "framework/ui/wx"

	#
	# The default resource directory for msfwx
	#
	DefaultResourceDirectory = Msf::Config.data_directory + File::SEPARATOR + "msfwx"

	#
	# Initializes a wx driver instance
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
		
		# Create the wxdriver global :(
		$wxdriver = self
		
		# Initialize the Wx application object
		@wxapp = Msf::Ui::Wx::MyApp.new()
	end

	#
	# Starts the main wx loop
	#
	def run
		ilog("msfwx has been started", LogSource)
		@wxapp.main_loop()
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
		::Wx::Icon.new(File.join(resource_directory, name))
	end

	#
	# The framework instance associated with this driver.
	#
	attr_reader   :framework

protected

	attr_writer   :framework # :nodoc:
	attr_accessor :opts      # :nodoc:

	#
	# Initializes logging for the web server.
	#
	def initialize_logging
		level = (opts['LogLevel'] || 0).to_i

		Msf::Logging.enable_log_source(LogSource, level)
	end

end

end
end
end
