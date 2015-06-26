# -*- coding: binary -*-

require 'msf/base/sessions/meeterpeter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meeterpeter session type
#
###
class meeterpeter_x86_BSD < Msf::Sessions::meeterpeter
  def initialize(rstream, opts={})
    super
    self.platform      = 'x86/bsd'
    self.binary_suffix = 'bso'
  end
end

end
end

