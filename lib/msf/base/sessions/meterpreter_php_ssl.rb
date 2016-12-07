# -*- coding: binary -*-
##
# $Id$
##

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_Php_Ssl < Msf::Sessions::Meterpreter_Php_Php
  def supports_ssl?
    true
  end
  
  def initialize(rstream, opts={})
    super
  end
end

end
end

