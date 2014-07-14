# -*- coding: binary -*-

module Msf::Proto::SSL::Callbacks
  def tls_postgres
    # postgresql TLS - works with all modern pgsql versions - 8.0 - 9.3
    # http://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
    get_data
    # the postgres SSLRequest packet is a int32(8) followed by a int16(1234),
    # int16(5679) in network format
    psql_sslrequest = [8].pack('N')
    psql_sslrequest << [1234, 5679].pack('n*')
    sock.put(psql_sslrequest)
    res = get_data
    unless res && res =~ /S/
      return nil
    end
    res
  end
end
