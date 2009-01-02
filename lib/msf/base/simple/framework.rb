require 'msf/base/simple'

module Msf
module Simple

###
#
# This class wraps the framework-core supplied Framework class and adds some
# helper methods for analyzing statistics as well as other potentially useful
# information that is directly necessary to drive the framework-core.
#
###
module Framework

	###
	#
	# Extends the framework.plugins class instance to automatically check in
	# the framework plugin's directory.
	#
	###
	module PluginManager

		#
		# Loads the supplied plugin by checking to see if it exists in the
		# framework default plugin path as necessary.
		#
		def load(path, opts = {})
			def_path = Msf::Config.plugin_directory + File::SEPARATOR + path

			if (File.exists?(def_path) or File.exists?(def_path + ".rb"))
				super(def_path, opts)
			else
				super
			end
		end

	end

	#
	# We extend modules when we're created, and we do it by registering a
	# general event subscriber.
	#
	include GeneralEventSubscriber

	#
	# Simplifies module instances when they're created.
	#
	def on_module_created(instance)
		Msf::Simple::Framework.simplify_module(instance)
	end

	ModuleSimplifiers =
		{
			MODULE_ENCODER => Msf::Simple::Encoder,
			MODULE_EXPLOIT => Msf::Simple::Exploit,
			MODULE_NOP     => Msf::Simple::Nop,
			MODULE_PAYLOAD => Msf::Simple::Payload,
			MODULE_AUX     => Msf::Simple::Auxiliary,
		}

	#
	# Create a simplified instance of the framework.  This routine takes a hash
	# of parameters as an argument.  This hash can contain:
	#
	#   OnCreateProc => A callback procedure that is called once the framework
	#   instance is created.
	#
	def self.create(opts = {})
		framework = Msf::Framework.new(opts)
		return simplify(framework, opts)
	end

	#
	# Extends a framework object that may already exist.
	#
	def self.simplify(framework, opts)

		# If the framework instance has not already been extended, do it now.
		if (framework.kind_of?(Msf::Simple::Framework) == false)
			framework.extend(Msf::Simple::Framework)
			framework.plugins.extend(Msf::Simple::Framework::PluginManager)
		end

		# Initialize the simplified framework
		framework.init_simplified()
		
		# Call the creation procedure if one was supplied
		if (opts['OnCreateProc'])
			opts['OnCreateProc'].call(framework)
		end

		# Initialize configuration and logging
		Msf::Config.init
		Msf::Logging.init


		# Load the configuration
		framework.load_config

		# Set the file that will be used to cache information about modules for
		# the purpose of providing demand-loaded modules.
		framework.modules.set_module_cache_file(
			File.join(Msf::Config.config_directory, 'modcache'))

		# Initialize the default module search paths
		if (Msf::Config.module_directory)
			framework.modules.add_module_path(Msf::Config.module_directory)
		end

		if (Msf::Config.user_module_directory)
			framework.modules.add_module_path(Msf::Config.user_module_directory)
		end

		# If additional module paths have been defined globally, then load them.
		# They should be separated by semi-colons.
		if framework.datastore['MsfModulePaths']
			framework.datastore['MsfModulePaths'].split(";").each { |path|
				framework.modules.add_module_path(path)
			}
		end

		# Register the framework as its own general event subscriber in this
		# instance
		framework.events.add_general_subscriber(framework)

		return framework
	end

	#
	# Simplifies a module instance if the type is supported by extending it
	# with the simplified module interface.
	#
	def self.simplify_module(instance)
		if ((ModuleSimplifiers[instance.type]) and
		    (instance.class.include?(ModuleSimplifiers[instance.type]) == false))
			instance.extend(ModuleSimplifiers[instance.type])

			instance.init_simplified
		end
	end

	##
	#
	# Simplified interface
	#
	##

	#
	# Initializes the simplified interface.
	#
	def init_simplified
		self.stats = Statistics.new(self)
	end

	#
	# Loads configuration, populates the root datastore, etc.
	#
	def load_config
		self.datastore.from_file(Msf::Config.config_file, 'framework/core')
	end

	#
	# Saves the module's datastore to the file
	#
	def save_config
		self.datastore.to_file(Msf::Config.config_file, 'framework/core')
	end

	#
	# Statistics.
	#
	attr_reader :stats

protected

	attr_writer :stats # :nodoc:

end

end
end
