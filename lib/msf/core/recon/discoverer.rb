require 'thread'
require 'rex/sync/event'

module Msf
class Recon

###
#
# This class acts as a base class for all recon modules that attempt to
# discover new entities and attributes of entities.  For instance, recon
# modules that attempt to discover the presence of a host, service, user, or
# other forms of entities are considered sub-classes of discoverer recon
# modules.  On top of that, recon modules that attempt to discover the
# attributes of any of the previously described entities are considered
# discoverer recon modules as well.
#
###
class Discoverer < Msf::Recon

	##
	#
	# The types of discoverer recon modules that are known about by default.
	#
	##
	module Type
		
		#
		# Unknown discoverer module type.
		#
		Unknown = 'unknown'

		#
		# Host discoverer.
		#
		Host = 'host'

		#
		# Host attribute discoverer.
		#
		HostAttribute = 'host attribute'

	end

	##
	#
	# The set of flags that discoverer modules can use to instruct the
	# framework (or themselves) on how to operate.
	#
	#
	module Flags
		#
		# This flag is used to indicate that a discoverer supports multithreaded
		# discovery.
		#
		Multithreaded = 0x01
	end

	require 'msf/core/recon/discoverer/host'
	require 'msf/core/recon/discoverer/service'

	#
	# Initializes the base of a recon discoverer module and adds any advanced
	# options that may be useful, like the number of threads the framework
	# should use for scanning.
	#
	def initialize(info = {})
		super

		# Attribute initialization
		self.discovery_threads = Array.new
		self.discovery_thread_mutex = Mutex.new
		self.discovery_thread_event = Rex::Sync::Event.new(false, false)

		# If the derived class supports multithreaded scanning, then allow the
		# user to set an option to control it
		if ((discoverer_flags & Flags::Multithreaded) != 0)
			register_advanced_options(
				[
					OptInt.new('ScanningThreads', [ 0, 'Number of threads to scan with', 1 ])
				], Msf::Recon::Discoverer)
		end
	end

	##
	#
	# Getters/Setters
	#
	##

	#
	# This method indicates that this recon module is a discoverer.
	#
	def recon_type
		Msf::Recon::Type::Discoverer
	end

	#
	# This method returns the type of discoverer recon module.
	#
	def discoverer_type
		Type::Unknown
	end

	#
	# This method returns the default discoverer flags that are used to drive
	# the host discovery process.
	#
	def discoverer_flags
		Flags::Multithreaded
	end

	##
	#
	# Core discoverer interface
	#
	##

	#
	# Initiates the discovery process in an implementation independent fashion.
	#
	def start_discovery
		# If the module is already discovering, then we don't need to start
		# again
		if (is_discovering)
			raise RuntimeError, "#{self.refname} is already discovering.", caller
		end

		# Validate that all the options are okay
		options.validate(datastore)

		# Reset the discovery event
		discovery_thread_event.reset

		# Get the default number of threads to spawn
		num_threads = default_scanning_threads;

		# If more scanning threads were supplied through an advanced option,
		# then let us use those
		if (datastore['ScanningThreads'] and
		    datastore['ScanningThreads'].to_i > 0)
			num_threads = datastore['ScanningThreads'].to_i
		end

		# Call a method that allows the derived class to pre-initialization
		# before actually starting
		discovery_startup

		# Spawn as many worker threads as were requested
		num_threads.times { |x|
			dlog("#{self.refname}: Spawning worker thread #{x+1}/#{num_threads}...", "core", LEV_3)

			spawn_discovery_thread
		}
	end

	#
	# Terminates the discovery process in an implementation independent
	# fashion.
	#
	def stop_discovery
		remaining = 0

		# Instruct all remaining discovery threads to stop.
		discovery_thread_mutex.synchronize {
			remaining = discovery_threads.length

			discovery_threads.each { |thr|
				thr.stop
			}
		}

		# Flush out the list of discovery threads
		discovery_threads.clear

		# Call the discovery complete method before the final wakeup.
		discovery_complete((remaining > 0) ? true : false)

		# Wake up any other threads that might be waiting for this operation to
		# complete
		discovery_thread_event.set
	end

	#
	# Waits for the recon discoverer to complete its operation.
	#
	def wait_for_completion(timeout = nil)
		discovery_thread_event.wait(timeout)
	end

	#
	# This method returns whether or not the recon module is discovering.
	#
	def is_discovering
		(discovery_threads.length > 0) ? true : false
	end

	##
	#
	# Defaults
	#
	##
	
	#
	# This method returns the default number of scanning threads for this
	# discoverer.
	#
	def default_scanning_threads
		1
	end

protected

	##
	#
	# Overridable protected methods
	#
	##

	#
	# This method is called when discovery is about to begin as the result of a
	# call being made to start_discovery.
	#
	def discovery_startup
	end

	#
	# This method is called when discovery is finished, whether it was aborted
	# or finished as normal.  If it was aborted, the first parameter will
	# indicate that fact by passing true.
	#
	def discovery_complete(aborted)
	end

	#
	# The entry point for all discovery threads.  This method should be
	# overridden by derived classes.
	#
	def discovery_thread
	end

	##
	#
	# Internal routines
	#
	##

	#
	# This method spawns a worker thread and adds it to the list of active
	# workers.
	#
	def spawn_discovery_thread
		# Synchronize the addition of the thread to the list of threads
		discovery_thread_mutex.synchronize {
			self.discovery_threads << Thread.new {
				begin
					# Perform the arbitrary discovery task.
					discovery_thread
	
					# Synchronize the removal of ourself from the list of threads.
					discovery_thread_mutex.synchronize {
						discovery_threads.delete(Thread.current)
	
						# If we detect that there are no more threads running, set the
						# event to indicate that we've reached completion.
						if (discovery_threads.length == 0)
							# Call the discovery complete method
							discovery_complete(false)

							discovery_thread_event.set
						end
					}
				rescue
					elog("Exception in discovery thread: #{$!}\n#{$@.join("\n")}")
				end
			}
		}
	end

	attr_accessor :discovery_threads # :nodoc:
	attr_accessor :discovery_thread_mutex # :nodoc:
	attr_accessor :discovery_thread_event # :nodoc:

end

end
end
