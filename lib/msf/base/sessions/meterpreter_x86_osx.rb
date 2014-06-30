# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x86_Osx < Msf::Sessions::Meterpreter
  def initialize(rstream, opts={})
    super
    self.platform      = 'x86/osx'
    self.binary_suffix = 'dylib'
  end
end

end
end

