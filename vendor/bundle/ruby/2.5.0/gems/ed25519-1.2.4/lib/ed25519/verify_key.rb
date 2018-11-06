# frozen_string_literal: true

module Ed25519
  # Public key for verifying digital signatures
  class VerifyKey
    # Create a Ed25519::VerifyKey from its serialized Twisted Edwards representation
    #
    # @param key [String] 32-byte string representing a serialized public key
    def initialize(key)
      Ed25519.validate_key_bytes(key)
      @key_bytes = key
    end

    # Verify an Ed25519 signature against the message
    #
    # @param signature [String] 64-byte string containing an Ed25519 signature
    # @param message [String] string containing message to be verified
    #
    # @raise Ed25519::VerifyError signature verification failed
    #
    # @return [true] message verified successfully
    def verify(signature, message)
      if signature.length != SIGNATURE_SIZE
        raise ArgumentError, "expected #{SIGNATURE_SIZE} byte signature, got #{signature.length}"
      end

      return true if Ed25519.provider.verify(@key_bytes, signature, message)
      raise VerifyError, "signature verification failed!"
    end

    # Return a compressed twisted Edwards coordinate representing the public key
    #
    # @return [String] bytestring serialization of this public key
    def to_bytes
      @key_bytes
    end
    alias to_str to_bytes

    # Show hex representation of serialized coordinate in string inspection
    def inspect
      "#<#{self.class}:#{@key_bytes.unpack('H*').first}>"
    end
  end
end
