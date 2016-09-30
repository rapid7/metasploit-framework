# -*- coding: binary -*-

module Msf

###
#
# Enum option.
#
###
class OptEnum < OptBase

  def type
    return 'enum'
  end

  def valid?(value=self.value, check_empty: true)
    return false if check_empty && empty_required_value?(value)
    return true if value.nil? and !required?

    (value and self.enums.include?(value.to_s))
  end

  def normalize(value=self.value)
    return nil if not self.valid?(value)
    return value.to_s
  end

  def desc=(value)
    self.desc_string = value

    self.desc
  end

  def desc
    if self.enums
      str = self.enums.join(', ')
    end
    "#{self.desc_string || ''} (Accepted: #{str})"
  end


protected

  attr_accessor :desc_string # :nodoc:

end

end
