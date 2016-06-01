# -*- coding: binary -*-

module Msf

###
#
# Integer option.
#
###
class OptInt < OptBase
  def type
    return 'integer'
  end

  def normalize(value)
    if value.to_s.match(/^0x[a-fA-F\d]+$/)
      value.to_i(16)
    else
      value.to_i
    end
  end

  def valid?(value, check_empty: true)
    return false if check_empty && empty_required_value?(value)

    if value and not value.to_s.match(/^0x[0-9a-fA-F]+$|^-?\d+$/)
      return false
    end

    return super
  end
end

end
