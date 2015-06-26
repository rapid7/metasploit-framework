# -*- coding: binary -*-

require 'msf/base/sessions/meeterpeter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meeterpeter session type
#
###
class meeterpeter_x86_Linux < Msf::Sessions::meeterpeter
  def initialize(rstream, opts={})
    super
    self.platform      = 'x86/linux'
    self.binary_suffix = 'lso'
  end
end

end
end

