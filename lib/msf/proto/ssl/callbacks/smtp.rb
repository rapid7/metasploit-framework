# -*- coding: binary -*-

module Msf::Proto::SSL::Callbacks
  def tls_smtp
    # https://tools.ietf.org/html/rfc3207
    get_data
    sock.put("EHLO #{Rex::Text.rand_text_alpha(10)}\r\n")
    res = get_data

    unless res && res =~ /STARTTLS/
      return nil
    end
    sock.put("STARTTLS\r\n")
    get_data
  end
end
