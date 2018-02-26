# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'
require 'msf/windows_error'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x64_Win < Msf::Sessions::Meterpreter
  def initialize(rstream, opts={})
    super
    self.base_platform = 'windows'
    self.base_arch = ARCH_X64
  end

  def lookup_error(code)
    Msf::WindowsError.description(code)
  end

  def supports_ssl?
    false
  end
end

end
end
