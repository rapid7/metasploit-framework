require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x86_Win < Msf::Sessions::Meterpreter
	def initialize(rstream)
		super
		self.platform      = 'x86/win32'
		self.binary_suffix = 'dll'
	end
end

end
end
