# -*- coding: binary -*-

module Msf

###
#
# Mult-byte character string option.
#
###
class OptString < OptBase
  def type
    return 'string'
  end

  def normalize(value)
    value
  end

  def valid?(value=self.value)
    value = normalize(value)
    return false if empty_required_value?(value)
    return super
  end
end

end
