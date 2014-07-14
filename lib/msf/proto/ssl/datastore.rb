# -*- coding: binary -*-

module Msf::Proto::SSL
  def response_timeout
    datastore['RESPONSE_TIMEOUT']
  end

  def tls_version
    value = datastore['TLS_VERSION']
    return TLS_VERSION[value] if TLS_VERSION.has_key?(value)
    raise("Unknown TLS_VERSION #{value}")
  end

  def xmpp_domain
    datastore['XMPPDOMAIN']
  end
end
