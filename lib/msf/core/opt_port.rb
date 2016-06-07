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

  def valid?(value, check_empty: true)
    port = normalize(value)
    super && port <= 65535 && port >= 0
  end
end

end
