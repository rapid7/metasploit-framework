# -*- coding: binary -*-

module Msf::Proto::SSL

  # generates a CLIENT_HELLO ssl/tls packet
  def client_hello(cipher_suites = DEFAULT_CIPHER_SUITES.values, extensions = nil)
      # Use current day for TLS time
      time_temp = Time.now
      time_epoch = Time.mktime(time_temp.year, time_temp.month, time_temp.day, 0, 0).to_i

      hello_data = [tls_version].pack('n') # Version TLS
      hello_data << [time_epoch].pack('N')    # Time in epoch format
      hello_data << Rex::Text.rand_text(28)   # Random
      hello_data << "\x00"                    # Session ID length
      hello_data << [cipher_suites.length * 2].pack('n') # Cipher Suites length (102)
      hello_data << cipher_suites.pack('n*')  # Cipher Suites
      hello_data << "\x01"                    # Compression methods length (1)
      hello_data << "\x00"                    # Compression methods: null

      # TODO
      if extensions
          hello_data_extensions = "\x00\x0f"      # Extension type (Heartbeat)
          hello_data_extensions << "\x00\x01"     # Extension length
          hello_data_extensions << "\x01"         # Extension data

          hello_data << [hello_data_extensions.length].pack('n')
          hello_data << hello_data_extensions
      end

      data = "\x01\x00"                      # Handshake Type: Client Hello (1)
      data << [hello_data.length].pack('n')  # Length
      data << hello_data

      ssl_record(RECORD_TYPE_HANDSHAKE, data)
  end
end
