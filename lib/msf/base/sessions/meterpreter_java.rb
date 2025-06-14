# -*- coding: binary -*-


module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_Java_Java < Msf::Sessions::Meterpreter
  def supports_ssl?
    false
  end
  def supports_zlib?
    false
  end
  def initialize(rstream, opts={})
    super
    self.base_platform = 'java'
    self.base_arch = ARCH_JAVA
  end

  def native_arch
    @native_arch ||= self.core.native_arch
  end
end

end
end
