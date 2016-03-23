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
    if !required? and value.to_s.empty?
      super
    else
      super && normalize(value) <= 65535 && normalize(value) >= 0
    end
  end
end

end
