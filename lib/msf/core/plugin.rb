require 'rex/sync/ref'

module Msf

###
#
# This module represents an abstract plugin that can be loaded into the
# context of a framework instance.  Plugins are meant to provide an easy way
# to augment the feature set of the framework by being able to load and unload
# them during the course of a framework's lifetime.  For instance, a plugin
# could be loaded to alter the default behavior of new sessions, such as by
# scripting meterpreter sessions that are created.  The possiblities are
# endless! 
#
# All plugins must exist under the Msf::Plugin namespace.  Plugins are
# reference counted to allow them to be loaded more than once if they're a
# singleton.
# 
###
class Plugin

	include Framework::Offspring
	include Rex::Ref

	#
	# Create an instance of the plugin using the supplied framework instance.
	# We use create instead of new directly so that singleton plugins can just
	# return their singleton instance.
	#
	def self.create(framework)
		new(framework)
	end

	#
	# Initializes the plugin instance with the supplied framework instance.
	#
	def initialize(framework)
		self.framework  = framework

		refinit
	end

	#
	# Allows the plugin to clean up as it is being unloaded.
	#
	def cleanup
	end

	##
	#
	# Accessors
	#
	##

	#
	# Returns the name of the plugin.
	#
	def name
		"unnamed"
	end

	#
	# A short description of the plugin.
	#
	def desc
	end

end

end
