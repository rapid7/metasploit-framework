# -*- coding: binary -*-

module Msf

###
#
# Proxies option
#
###
class OptProxies < OptBase

  def type
    'proxies'
  end

  def validate_on_assignment?
    true
  end

  def normalize(value)
    value
  end

  def valid?(value, check_empty: true, datastore: nil)
    return false if check_empty && empty_required_value?(value)

    begin
      Rex::Socket::Proxies.parse(value)
    rescue Rex::RuntimeError
      return false
    end

    true
  end
end

end
