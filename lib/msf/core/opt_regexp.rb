# -*- coding: binary -*-

module Msf

###
#
# Regexp option
#
###
class OptRegexp < OptBase
  def type
    return 'regexp'
  end

  def valid?(value, check_empty: true)
    if check_empty && empty_required_value?(value)
      return false
    elsif value.nil?
      return true
    end

    begin
      Regexp.compile(value)
      return super
    rescue RegexpError, TypeError
      return false
    end
  end

  def normalize(value)
    if value.nil? || value.kind_of?(Regexp)
      value
    else
      Regexp.compile(value.to_s)
    end
  end

  def display_value(value)
    if value.kind_of?(Regexp)
      return value.source
    elsif value.kind_of?(String)
      return display_value(normalize(value))
    end
    super
  end
end

end
