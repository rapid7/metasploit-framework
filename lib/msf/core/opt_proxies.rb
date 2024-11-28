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

    parsed = Rex::Socket::Proxies.parse(value)
    allowed_types = Rex::Socket::Proxies.supported_types
    parsed.all? do |type, host, port|
      allowed_types.include?(type) && host.present? && port.present?
    end
  end
end

end
