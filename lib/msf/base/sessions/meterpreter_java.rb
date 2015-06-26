# -*- coding: binary -*-

require 'msf/base/sessions/meeterpeter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meeterpeter session type
#
###
class meeterpeter_Java_Java < Msf::Sessions::meeterpeter
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
end

end
end

