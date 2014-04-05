# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x86_BSD < Msf::Sessions::Meterpreter
  def initialize(rstream, opts={})
    super
    self.platform      = 'x86/bsd'
    self.binary_suffix = 'bso'
  end
end

end
end

