module Msf

###
# 
# This class illustrates a sample plugin.
#
###
class Plugin::Sample < Msf::Plugin

	def initialize(framework) # :nodoc:
		super
	end

	def name # :nodoc:
		"sample"
	end

	def desc # :nodoc:
		"Demonstrates using framework plugins"
	end

end

end
