# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x86_Linux < Msf::Sessions::Meterpreter
  def initialize(rstream, opts={})
    super
    self.platform      = 'x86/linux'
    self.binary_suffix = 'lso'
  end
end

end
end

