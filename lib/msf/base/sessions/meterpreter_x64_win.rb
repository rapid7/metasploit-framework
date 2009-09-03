require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x64_Win < Msf::Sessions::Meterpreter
	def self.platform
		'x64/win64'
	end
	def self.binary_suffix
		'x64.dll'
	end
end

end
end
