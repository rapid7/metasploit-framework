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

  def valid?(value)
    unless super
      return false
    end
    return true if (not required? and value.nil?)

    begin
      Regexp.compile(value)

      return true
    rescue RegexpError, TypeError
      return false
    end
  end

  def normalize(value)
    return nil if value.nil?
    return Regexp.compile(value.to_s)
  end

  def display_value(value)
    if value.kind_of?(Regexp)
      return value.source
    elsif value.kind_of?(String)
      return display_value(normalize(value))
    end

    return super
  end
end

end
