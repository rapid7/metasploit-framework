# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

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
    self.platform      = 'java/java'
    self.binary_suffix = 'jar'
  end
  
  def load_android() 
    self.platform      = 'java/android'  
    console.disable_output = true
    console.run_single('load android')
  end
  
end

end
end

