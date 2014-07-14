# -*- coding: binary -*-

module Msf::Proto::SSL::Callbacks
  def tls_pop3
    # http://tools.ietf.org/html/rfc2595
    get_data
    sock.put("CAPA\r\n")
    res = get_data
    if res.nil? || res =~ /^-/ || res !~ /STLS/
      return nil
    end
    sock.put("STLS\r\n")
    res = get_data
    if res.nil? || res =~ /^-/
      return nil
    end
    res
  end
end
