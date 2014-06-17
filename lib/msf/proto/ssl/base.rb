# -*- coding: binary -*-

module Msf::Proto::SSL
  def ssl_record(type, data)
    record = [type, tls_version, data.length].pack('Cnn')
    record << data
  end
end
