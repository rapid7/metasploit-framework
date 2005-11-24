require 'rex/proto/http'
require 'msf/core'
require 'msf/base'
require 'msf/ui'
require 'msf/ui/web/request_dispatcher'

module Msf
module Ui
module Web


###
#
# This class implements a user interface driver on a web interface.
#
###
class Driver < Msf::Ui::Driver

	include RequestDispatcher

	ConfigCore  = "framework/core"
	ConfigGroup = "framework/ui/web"

	#
	# The msfweb resource handler that wrappers the default Erb handler.
	#
	class ResourceHandler < Rex::Proto::Http::Handler::Erb
		def initialize(server, root_path, framework, driver, opts = {})
			opts['ErbCallback'] = ::Proc.new { |erb, cli, request, response| 
				query_string = request.qstring
				meta_vars    = request.meta_vars
				erb.result(binding)
			}

			super(server, root_path, opts)

			self.framework = framework
			self.driver    = driver
		end

		attr_accessor :framework # :nodoc:
		attr_accessor :driver    # :nodoc:
	end

	#
	# The default port to listen for HTTP requests on.
	#
	DefaultPort = 55555

	#
	# The default host to listen for HTTP requests on.
	#
	DefaultHost = "127.0.0.1"

	#
	# The default root directory for requests.
	#
	DefaultRoot = "/"

	#
	# The default local directory for msfweb.
	#
	DefaultLocalDirectory = Msf::Config.data_directory + File::SEPARATOR + "msfweb"

	#
	# The default index script.
	#
	DefaultIndex = "index.rhtml"

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

		# Initialize logging
		initialize_logging
		
		# Initialize attributes
		self.framework = Msf::Simple::Framework.create

		# Initialize the termination event.
		self.term_event = Rex::Sync::Event.new

		# Include common helper stuff.  If there is no common stuff to be
		# included, then we'll just catch the exception and move on with our
		# life.
		begin
			if ($:.include?(server_local_directory) == false)
				$:.unshift(server_local_directory)
				require 'msfweb_common'
			end
		rescue
		end
	end

	#
	# Starts the HTTP server and waits for termination.
	#
	def run
		self.service = Rex::ServiceManager.start(Rex::Proto::Http::Server,
				port = (opts['ServerPort'] || DefaultPort).to_i,
				host = (opts['ServerHost'] || DefaultHost))

		ilog("Web server started on #{host}:#{port}", LogSource)

		# Mount the server root directory on the web server instance.  We pass
		# it a custom ErbCallback so that we can have it run in a context that
		# has the framework instance defined.
		service.mount(
			server_root,
			ResourceHandler, 
			false,
			server_local_directory,	
			framework,
			self)

		# Wait for the termination event to be set.
		term_event.wait

		# Stop the source and clean it up.
		Rex::ServiceManager.stop_service(service)

		service.deref
		
		true
	end

	#
	# Sets the event that will cause the web service to terminate.
	#
	def terminate
		term_event.set
	end

	#
	# Returns the root resource name, such as '/msfweb'.
	#
	def server_root
		opts['ServerRoot'] || DefaultRoot
	end

	#
	# Returns the server index, such as 'index.rhtml'.
	#
	def server_index
		opts['ServerIndex'] || DefaultIndex
	end

	#
	# Returns the local directory that will hold the files to be serviced.
	#
	def server_local_directory
		opts['ServerLocalDirectory'] || DefaultLocalDirectory
	end

	#
	# The framework instance associated with this driver.
	#
	attr_reader   :framework

protected

	attr_writer   :framework # :nodoc:
	attr_accessor :opts      # :nodoc:

	#
	# The internal event used to cause the web service to stop.
	#
	attr_accessor :term_event

	#
	# The internal service context.
	#
	attr_accessor :service

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
