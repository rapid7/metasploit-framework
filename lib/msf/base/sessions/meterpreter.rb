require 'msf/base'
require 'rex/post/meterpreter'

module Msf
module Sessions

###
#
# This class represents a session compatible interface to a meterpreter server
# instance running on a remote machine.  It provides the means of interacting
# with the server instance both at an API level as well as at a console level.
#
###
class Meterpreter < Rex::Post::Meterpreter::Client

	#
	# The meterpreter session is interactive
	#
	include Msf::Session
	include Msf::Session::Interactive
	include Msf::Session::Comm

	#
	# Find out of the script exists (and if so, which path)
	#
	ScriptBase     = Msf::Config.script_directory + Msf::Config::FileSep + "meterpreter"
	UserScriptBase = Msf::Config.user_script_directory + Msf::Config::FileSep + "meterpreter"

	def self.find_script_path(script)
		# Find the full file path of the specified argument
		check_paths =
			[
				script,
				ScriptBase + Msf::Config::FileSep + "#{script}",
				ScriptBase + Msf::Config::FileSep + "#{script}.rb",
				UserScriptBase + Msf::Config::FileSep + "#{script}",
				UserScriptBase + Msf::Config::FileSep + "#{script}.rb"
			]

		full_path = nil

		# Scan all of the path combinations
		check_paths.each { |path|
			if ::File.exists?(path)
				full_path = path
				break
			end
		}

		full_path
	end


	#
	# Initializes a meterpreter session instance using the supplied rstream
	# that is to be used as the client's connection to the server.
	#
	def initialize(rstream, opts={})
		super

		#
		# Initialize the meterpreter client
		#
		self.init_meterpreter(rstream, opts)

		#
		# Create the console instance
		#
		self.console = Rex::Post::Meterpreter::Ui::Console.new(self)
	end

	#
	# Returns the session type as being 'meterpreter'.
	#
	def type
		"meterpreter"
	end

	##
	#
	# Msf::Session overrides
	#
	##

	#
	# Cleans up the meterpreter client session.
	#
	def cleanup
		cleanup_meterpreter

		super
	end

	#
	# Returns the session description.
	#
	def desc
		"Meterpreter"
	end

	##
	#
	# Msf::Session::Interactive implementors
	#
	##

	#
	# Initializes the console's I/O handles.
	#
	def init_ui(input, output)
		self.user_input = input
		self.user_output = output
		console.init_ui(input, output)
		console.set_log_source(log_source)

		super
	end

	#
	# Resets the console's I/O handles.
	#
	def reset_ui
		console.unset_log_source
		console.reset_ui
	end

	#
	# Terminates the session
	#
	def kill
		begin
			cleanup_meterpreter
			self.sock.close
		rescue ::Exception
		end
		framework.sessions.deregister(self)
	end

	#
	# Run the supplied command as if it came from suer input.
	#
	def queue_cmd(cmd)
		console.queue_cmd(cmd)
	end

	#
	# Explicitly runs a command.
	#
	def run_cmd(cmd)
		console.run_single(cmd)
	end

	#
	# Executes the supplied script.
	#
	def execute_script(script, args)

		full_path = self.class.find_script_path(script)

		# No path found?  Weak.
		if full_path.nil?
			print_error("The specified script could not be found: #{script}")
			return true
		end

		execute_file(full_path, args)
	end

	#
	# Load the stdapi extension.
	#
	def load_stdapi()
		original = console.disable_output

		console.disable_output = true
		console.run_single('use stdapi')
		console.disable_output = original
	end

	#
	# Load the priv extension.
	#
	def load_priv()
		original = console.disable_output

		console.disable_output = true
		console.run_single('use priv')
		console.disable_output = original
	end

	#
	# Populate the session information.
	#
	def load_session_info()
		begin
			::Timeout.timeout(20) do
				username  = self.sys.config.getuid
				sysinfo   = self.sys.config.sysinfo
				self.info = "#{username} @ #{sysinfo['Computer']}"
			end
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			# $stderr.puts "ERROR: #{e.class} #{e} #{e.backtrace}"
		end
	end

	#
	# Interacts with the meterpreter client at a user interface level.
	#
	def _interact
		framework.events.on_session_interact(self)
		# Call the console interaction subsystem of the meterpreter client and
		# pass it a block that returns whether or not we should still be
		# interacting.  This will allow the shell to abort if interaction is
		# canceled.
		console.interact { self.interacting != true }

		# If the stop flag has been set, then that means the user exited.  Raise
		# the EOFError so we can drop this bitch like a bad habit.
		raise EOFError if (console.stopped? == true)
	end


	##
	#
	# Msf::Session::Comm implementors
	#
	##

	#
	# Creates a connection based on the supplied parameters and returns it to
	# the caller.  The connection is created relative to the remote machine on
	# which the meterpreter server instance is running.
	#
	def create(param)
		sock = nil

		# Notify handlers before we create the socket
		notify_before_socket_create(self, param)

		sock = net.socket.create(param)

		# sf: unsure if we should raise an exception or just return nil. returning nil for now.
		#if( sock == nil )
		#  raise Rex::UnsupportedProtocol.new(param.proto), caller
		#end

		# Notify now that we've created the socket
		notify_socket_created(self, sock, param)

		# Return the socket to the caller
		sock
	end

	attr_accessor :platform
	attr_accessor :binary_suffix
	attr_accessor :console # :nodoc:
	attr_accessor :skip_ssl
	attr_accessor :target_id

protected

	attr_accessor :rstream # :nodoc:

end

end
end

