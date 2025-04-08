module Msf::Exploit::Remote::Pkcs12

  class StoredPkcs12
    def initialize(pkcs12)
      @pkcs12 = pkcs12
    end

    def id
      @pkcs12.id
    end

    def openssl_pkcs12
      private_cred.openssl_pkcs12
    end

    def adcs_ca
      private_cred.adcs_ca || ''
    end

    def adcs_template
      private_cred.adcs_template || ''
    end

    def private_cred
      @pkcs12.private
    end

    def username
      @pkcs12.public&.username || ''
    end

    def realm
      @pkcs12.realm&.value || ''
    end

    def status
      private_cred.status || ''
    end

    # @return [TrueClass, FalseClass] True if the certificate is valid within the not_before/not_after, false otherwise
    def expired?(now = Time.now)
      cert = openssl_pkcs12.certificate
      !now.between?(cert.not_before, cert.not_after)
    end
  end
end

