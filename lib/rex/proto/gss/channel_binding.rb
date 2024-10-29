require 'rubyntlm'

module Rex::Proto::Gss
  class ChannelBinding < Net::NTLM::ChannelBinding
    attr_reader :digest_algorithm
    def initialize(channel_data, unique_prefix: 'tls-server-end-point', digest_algorithm: 'SHA256')
      super(channel_data)
      @unique_prefix = unique_prefix
      @digest_algorithm = digest_algorithm
    end

    def channel_hash
      @channel_hash ||= OpenSSL::Digest.new(@digest_algorithm, channel)
    end

    def self.create(peer_cert)
      super(peer_cert.to_der)
    end

    def self.from_tls_cert(peer_cert)
      digest_algorithm = 'SHA256'
      if peer_cert.signature_algorithm
        # see: https://learn.microsoft.com/en-us/archive/blogs/openspecification/ntlm-and-channel-binding-hash-aka-extended-protection-for-authentication
        normalized_name = OpenSSL::Digest.new(peer_cert.signature_algorithm).name.upcase
        unless %[ MD5 SHA1 ].include?(normalized_name)
          digest_algorithm = normalized_name
        end
      end

      new(peer_cert.to_der, unique_prefix: 'tls-server-end-point', digest_algorithm: digest_algorithm)
    end
  end
end
