module Msf

###
# 
# This class illustrates a sample plugin.  Plugins can change the behavior of
# the framework by adding new features, new user interface commands, or
# through any other arbitrary means.  They are designed to have a very loose
# definition in order to make them as useful as possible.
#
###
class Plugin::Sample < Msf::Plugin

	#
	# The constructor is called when an instance of the plugin is created.  The
	# framework instance that the plugin is being associated with is passed in
	# the framework parameter.  Plugins should call the parent constructor when
	# inheriting from Msf::Plugin to ensure that the framework attribute on
	# their instance gets set.
	#
	def initialize(framework, opts)
		super

		print_status("Sample plugin loaded.")
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"sample"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Demonstrates using framework plugins"
	end

end

end
