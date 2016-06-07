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
    if required?
      super && port <= 65535 && port >= 0
    elsif value.present?
      check_empty = false
      super
    else
      true
    end
  end
end

end
