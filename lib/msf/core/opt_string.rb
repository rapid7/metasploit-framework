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

  def validate_on_assignment?
    false
  end

  def normalize(value)
    if (value.to_s =~ /^file:(.*)/)
      path = $1
      begin
        value = File.read(path)
      rescue ::Errno::ENOENT, ::Errno::EISDIR
        value = nil
      end
    end
    value
  end

  def valid?(value=self.value, check_empty: true)
    value = normalize(value)
    return false if check_empty && empty_required_value?(value)
    return super(value, check_empty: false)
  end
end

end
