require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x86_Linux < Msf::Sessions::Meterpreter
	def self.platform
		'x86/linux'
	end
	def self.binary_suffix
		'lso'
	end
end

end
end
