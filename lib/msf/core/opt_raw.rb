# -*- coding: binary -*-

module Msf

###
#
# Raw, arbitrary data option.
#
###
class OptRaw < OptBase
  def type
    return 'raw'
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
