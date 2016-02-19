# -*- coding: binary -*-

module Msf

###
#
# Network port option.
#
###
class OptPort < OptBase
  def type
    return 'port'
  end

  def normalize(value)
    value.to_i
  end

  def valid?(value)
    return false if empty_required_value?(value)

    if ((value != nil and value.to_s.empty? == false) and
        ((value.to_s.match(/^\d+$/) == nil or value.to_i < 0 or value.to_i > 65535)))
      return false
    end

    return super
  end
end

end
