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

  def valid?(value=self.value)
    value = normalize(value)
    return false if empty_required_value?(value)
    return super
  end
end

end
