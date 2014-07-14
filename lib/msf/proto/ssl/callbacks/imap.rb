# -*- coding: binary -*-

module Msf::Proto::SSL::Callbacks
  def tls_imap
    # http://tools.ietf.org/html/rfc2595
    get_data
    sock.put("a001 CAPABILITY\r\n")
    res = get_data
    unless res && res =~ /STARTTLS/i
      return nil
    end
    sock.put("a002 STARTTLS\r\n")
    get_data
  end
end
