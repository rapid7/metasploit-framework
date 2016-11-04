# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-independent meterpreter session type
#
###
class Meterpreter_Multi < Msf::Sessions::Meterpreter
  def initialize(rstream, opts={})
    super
    self.base_platform = 'unknown'
    self.base_arch = ARCH_UNKNOWN

    # TODO: can we read the opts and find the UUID to instantiate the right
    # session type? Is it important?
  end
end

end
end

