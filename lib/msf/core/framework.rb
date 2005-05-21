require 'Core'

module Msf

###
#
# Framework
# ---------
#
# This class is the primary context that modules, scripts, and user
# interfaces interact with.  It ties everything together.
#
###
class Framework

	include Msf::Logging::LogDispatcher

	def initialize()
		self.events   = EventDispatcher.new
#		self.encoders = EncoderManager.new
#		self.exploits = ExploitManager.new
#		self.nops     = NopManager.new
#		self.payloads = PayloadManager.new
#		self.recon    = ReconManager.new

		super
	end

	attr_reader   :events
	attr_reader   :ui
	attr_reader   :encoders
	attr_reader   :exploits
	attr_reader   :nops
	attr_reader   :payloads
	attr_reader   :recon

protected

	attr_writer   :events
	attr_writer   :ui
	attr_writer   :encoders
	attr_writer   :exploits
	attr_writer   :nops
	attr_writer   :payloads
	attr_writer   :recon

end

end
