# -*- coding: binary -*-

module Msf

###
#
# Network port option.
#
###
class OptPort < OptInt
  def type
    return 'port'
  end

  def valid?(value)
    super && normalize(value) <= 65535 && normalize(value) > 0
  end
end

end
