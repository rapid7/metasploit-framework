# -*- coding: binary -*-

module Msf

###
#
# Boolean option.
#
###
class OptBool < OptBase

  TrueRegex = /^(y|yes|t|1|true)$/i

  def type
    return 'bool'
  end

  def valid?(value, check_empty: true)
    return false if empty_required_value?(value)

    if ((value != nil and
        (value.to_s.empty? == false) and
        (value.to_s.match(/^(y|yes|n|no|t|f|0|1|true|false)$/i) == nil)))
      return false
    end

    true
  end

  def normalize(value)
    if(value.nil? or value.to_s.match(TrueRegex).nil?)
      false
    else
      true
    end
  end

  def is_true?(value)
    return normalize(value)
  end

  def is_false?(value)
    return !is_true?(value)
  end

end

end
