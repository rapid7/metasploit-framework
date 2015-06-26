# -*- coding: binary -*-

require 'msf/base/sessions/meeterpeter'
require 'msf/windows_error'

module Msf
module Sessions

###
#
# This class creates a platform-specific meeterpeter session type
#
###
class meeterpeter_x86_Win < Msf::Sessions::meeterpeter
  def initialize(rstream,opts={})
    super
    self.platform      = 'x86/win32'
    self.binary_suffix = 'x86.dll'
  end

  def lookup_error(code)
    Msf::WindowsError.description(code)
  end
end

end
end
