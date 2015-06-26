# -*- coding: binary -*-

require 'msf/base/sessions/meeterpeter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meeterpeter session type
#
###
class meeterpeter_Php_Php < Msf::Sessions::meeterpeter
  def supports_ssl?
    false
  end
  def supports_zlib?
    false
  end
  def initialize(rstream, opts={})
    super
    self.platform      = 'php/php'
    self.binary_suffix = 'php'
  end
end

end
end

