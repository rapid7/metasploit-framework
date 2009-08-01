require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x86_Win < Msf::Sessions::Meterpreter
	def self.platform
		'x86/win32'
	end
	def self.binary_suffix
		'dll'
	end
end

end
end
