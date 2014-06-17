# -*- coding: binary -*-

module Msf::Proto::SSL::Callbacks
  def tls_ftp
    # http://tools.ietf.org/html/rfc4217
    res = sock.get(response_timeout)
    return nil if res.nil?
    sock.put("AUTH TLS\r\n")
    res = get_data
    return nil if res.nil?
    if res !~ /^234/
      # res contains the error message
      vprint_error("#{peer} - FTP error: #{res.strip}")
      return nil
    end
    res
  end
end
