# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a android meterpreter session type
#
###
class Meterpreter_Java_Android < Msf::Sessions::Meterpreter
	def supports_ssl?
		false
	end
	def supports_zlib?
		false
	end
	
	def initialize(rstream, opts={})
		super
		self.platform      = 'java/android'
		self.binary_suffix = 'jar'
	end
	
	def load_android()
		original = console.disable_output
		console.disable_output = true
		console.run_single('load android')
		#console.disable_output = original
	end
	
end

end
end

