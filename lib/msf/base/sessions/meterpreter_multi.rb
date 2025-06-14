# -*- coding: binary -*-


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
    self.base_platform = 'multi'
    self.base_arch = ARCH_ANY
  end

  def self.create_session(rstream, opts={})
    # TODO: fill in more cases here
    case opts[:payload_uuid].platform
    when 'python'
      return Msf::Sessions::Meterpreter_Python_Python.new(rstream, opts)
    when 'java'
      return Msf::Sessions::Meterpreter_Java_Java.new(rstream, opts)
    when 'android'
      return Msf::Sessions::Meterpreter_Java_Android.new(rstream, opts)
    when 'php'
      return Msf::Sessions::Meterpreter_Php_Php.new(rstream, opts)
    when 'windows'
      if opts[:payload_uuid].arch == ARCH_X86
        return Msf::Sessions::Meterpreter_x86_Win.new(rstream, opts)
      end
      return Msf::Sessions::Meterpreter_x64_Win.new(rstream, opts)
    end

    # TODO: what should we do when we get here?
    # For now lets return a generic for basic functionality with http(s) communication
    Msf::Sessions::Meterpreter.new(rstream, opts)
  end
end

end
end

