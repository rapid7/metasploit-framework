module Rex::Proto::X509

  class Request
    def self.create_csr(private_key, cn, algorithm = 'SHA256')
      request = OpenSSL::X509::Request.new
      request.subject = OpenSSL::X509::Name.new([
        ['CN', cn, OpenSSL::ASN1::UTF8STRING]
      ])
      request.public_key = private_key.public_key

      yield request if block_given?

      request.sign(private_key, OpenSSL::Digest.new(algorithm))
      request
    end
  end

end
