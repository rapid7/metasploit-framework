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
	DefaultRoot = "/msfweb"

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
	end

	#
	# Starts the HTTP server and waits for termination.
	#
	def run
		self.service = Rex::ServiceManager.start(Rex::Proto::Http::Server,
				port = (opts['ServerPort'] || DefaultPort).to_i,
				host = (opts['ServerHost'] || DefaultHost))

		ilog("Web server started on #{host}:#{port}", LogSource)

		service.add_resource(
			server_root,
			'Directory' => true,
			'Proc' => Proc.new { |cli, req|
				on_request(cli, req)
			})

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
	# Returns the root resource name, such as '/msfweb'
	#
	def server_root
		opts['ServerRoot'] || DefaultRoot
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

	#
	# Called when an HTTP request comes in from a client that needs to be
	# dispatched.
	#
	def on_request(cli, req)
		parts = req.resource.gsub(server_root, '').split(/\//)

		
	end
	
end

end
end
end
