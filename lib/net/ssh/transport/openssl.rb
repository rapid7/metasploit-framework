require 'openssl'
require 'net/ssh/buffer'

module OpenSSL

  # This class is originally defined in the OpenSSL module. As needed, methods
  # have been added to it by the Net::SSH module for convenience in dealing with
  # SSH functionality.
  class BN

    # Converts a BN object to a string. The format used is that which is
    # required by the SSH2 protocol.
    def to_ssh
      if zero?
        return [0].pack("N")
      else
        buf = to_s(2)
        if buf.getbyte(0)[7] == 1
          return [buf.length+1, 0, buf].pack("NCA*")
        else
          return [buf.length, buf].pack("NA*")
        end
      end
    end

  end

  module PKey

    class PKey
      def fingerprint
        @fingerprint ||= OpenSSL::Digest::MD5.hexdigest(to_blob).scan(/../).join(":")
      end
    end

    # This class is originally defined in the OpenSSL module. As needed, methods
    # have been added to it by the Net::SSH module for convenience in dealing
    # with SSH functionality.
    class DH

      # Determines whether the pub_key for this key is valid. (This algorithm
      # lifted more-or-less directly from OpenSSH, dh.c, dh_pub_is_valid.)
      def valid?
        return false if pub_key.nil? || pub_key < 0
        bits_set = 0
        pub_key.num_bits.times { |i| bits_set += 1 if pub_key.bit_set?(i) }
        return ( bits_set > 1 && pub_key < p )
      end

    end

    # This class is originally defined in the OpenSSL module. As needed, methods
    # have been added to it by the Net::SSH module for convenience in dealing
    # with SSH functionality.
    class RSA

      # Returns "ssh-rsa", which is the description of this key type used by the
      # SSH2 protocol.
      def ssh_type
        "ssh-rsa"
      end

      # Converts the key to a blob, according to the SSH2 protocol.
      def to_blob
        @blob ||= Net::SSH::Buffer.from(:string, ssh_type, :bignum, e, :bignum, n).to_s
      end

      # Verifies the given signature matches the given data.
      def ssh_do_verify(sig, data)
        verify(OpenSSL::Digest::SHA1.new, sig, data)
      end

      # Returns the signature for the given data.
      def ssh_do_sign(data)
        sign(OpenSSL::Digest::SHA1.new, data)
      end
    end

    # This class is originally defined in the OpenSSL module. As needed, methods
    # have been added to it by the Net::SSH module for convenience in dealing
    # with SSH functionality.
    class DSA

      # Returns "ssh-dss", which is the description of this key type used by the
      # SSH2 protocol.
      def ssh_type
        "ssh-dss"
      end

      # Converts the key to a blob, according to the SSH2 protocol.
      def to_blob
        @blob ||= Net::SSH::Buffer.from(:string, ssh_type,
          :bignum, p, :bignum, q, :bignum, g, :bignum, pub_key).to_s
      end

      # Verifies the given signature matches the given data.
      def ssh_do_verify(sig, data)
        sig_r = sig[0,20].unpack("H*")[0].to_i(16)
        sig_s = sig[20,20].unpack("H*")[0].to_i(16)
        a1sig = OpenSSL::ASN1::Sequence([
           OpenSSL::ASN1::Integer(sig_r),
           OpenSSL::ASN1::Integer(sig_s)
        ])
        return verify(OpenSSL::Digest::DSS1.new, a1sig.to_der, data)
      end

      # Signs the given data.
      def ssh_do_sign(data)
        sig = sign( OpenSSL::Digest::DSS1.new, data)
        a1sig = OpenSSL::ASN1.decode( sig )

        sig_r = a1sig.value[0].value.to_s(2)
        sig_s = a1sig.value[1].value.to_s(2)

        if sig_r.length > 20 || sig_s.length > 20
          raise OpenSSL::PKey::DSAError, "bad sig size"
        end

        sig_r = "\0" * ( 20 - sig_r.length ) + sig_r if sig_r.length < 20
        sig_s = "\0" * ( 20 - sig_s.length ) + sig_s if sig_s.length < 20

        return sig_r + sig_s
      end
    end

  end

end
