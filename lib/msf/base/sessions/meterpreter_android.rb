# -*- coding: binary -*-

require 'msf/base/sessions/meeterpeter'
require 'msf/base/sessions/meeterpeter_java'
require 'msf/base/sessions/meeterpeter_options'

module Msf
module Sessions

###
#
# This class creates a platform-specific meeterpeter session type
#
###
class meeterpeter_Java_Android < Msf::Sessions::meeterpeter_Java_Java

  def initialize(rstream, opts={})
    super
    self.platform = 'java/android'
  end

  def load_android
    original = console.disable_output
    console.disable_output = true
    console.run_single('load android')
    console.disable_output = original
  end

end

end
end

