# -*- coding: binary -*-

module Msf

###
#
# Mult-byte character string option.
#
###
class OptString < OptBase

  # This adds a length parameter to check for the maximum length of strings.
  def initialize(in_name, attrs = [],
               required: false, desc: nil, default: nil, enums: [], regex: nil, aliases: [], max_length: 0)
    super
  end

  def type
    return 'string'
  end

  def validate_on_assignment?
    true
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
    return false if max_length_value?(value)
    return super(check_empty: false)
  end
end

end
