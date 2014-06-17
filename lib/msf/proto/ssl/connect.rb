# -*- coding: binary -*-

module Msf::Proto::SSL

  # establishes a connect and parses the server response
  def establish_connect(cipher_suites = DEFAULT_CIPHER_SUITES.values)
    connect

    unless tls_callback == 'None'
      vprint_status("#{peer} - Trying to start SSL via #{tls_callback}")
      
      res = self.send(TLS_CALLBACKS[tls_callback])

      if res.nil?
        vprint_error("#{peer} - STARTTLS failed...")
        return nil
      end
    end

    vprint_status("#{peer} - Sending Client Hello...")
    sock.put(client_hello(cipher_suites, 1))

    server_hello = sock.get(response_timeout)
    unless server_hello
      vprint_error("#{peer} - No Server Hello after #{response_timeout} seconds...")
      return nil
    end

    server_resp_parsed = parse_ssl_record(server_hello)

    if server_resp_parsed.nil?
      vprint_error("#{peer} - Server Hello Not Found")
      return nil
    end

    server_resp_parsed
  end

end
