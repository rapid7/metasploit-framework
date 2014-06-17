  # -*- coding: binary -*-

module Msf::Proto::SSL::Parsers

  # Parse certificate data
  def parse_certificate_data(data)
    # get certificate data length
    unpacked = data.unpack('Cn')
    cert_len_padding = unpacked[0]
    cert_len = unpacked[1]
    vprint_debug("\t\tCertificates length: #{cert_len}")
    # contains multiple certs
    already_read = 3
    cert_counter = 0
    while already_read < cert_len
      start = already_read
      cert_counter += 1
      # get single certificate length
      single_cert_unpacked = data[start, 3].unpack('Cn')
      single_cert_len_padding = single_cert_unpacked[0]
      single_cert_len =  single_cert_unpacked[1]
      vprint_debug("\t\tCertificate ##{cert_counter}:")
      vprint_debug("\t\t\tCertificate ##{cert_counter}: Length: #{single_cert_len}")
      certificate_data = data[(start + 3), single_cert_len]
      cert = OpenSSL::X509::Certificate.new(certificate_data)
      # First received certificate is the one from the server
      @cert = cert if @cert.nil?
      #vprint_debug("Got certificate: #{cert.to_text}")
      vprint_debug("\t\t\tCertificate ##{cert_counter}: #{cert.inspect}")
      already_read = already_read + single_cert_len + 3
    end

    # TODO: return hash with data
    true
  end
end
