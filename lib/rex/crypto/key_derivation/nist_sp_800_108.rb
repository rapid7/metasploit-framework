require 'openssl'

module Rex::Crypto::KeyDerivation::NIST_SP_800_108

  # Generates key material using the NIST SP 800-108 R1 counter mode KDF.
  #
  # @param length [Integer] The desired output length of each key in bytes.
  # @param prf [Proc] The pseudorandom function used for key derivation.
  # @param keys [Integer] The number of derived keys to generate.
  # @param label [String] Optional label to distinguish different derivations.
  # @param context [String] Optional context to bind the key derivation to specific information.
  #
  # @return [Array<String>] An array of derived keys as binary strings, regardless of the number requested.
  def self.counter(length, prf, keys: 1, label: ''.b, context: ''.b)
    key_block = ''

    counter = 0
    while key_block.length < (length * keys)
      counter += 1
      raise RangeError.new("counter overflow") if counter > 0xffffffff

      info = [ counter ].pack('L>') + label + "\x00".b + context + [ length * keys * 8 ].pack('L>')
      key_block << prf.call(info)
    end

    key_block.bytes.each_slice(length).to_a[...keys].map { |slice| slice.pack('C*') }
  end

  # Generates key material using the NIST SP 800-108 R1 counter mode KDF with HMAC.
  #
  # @param secret [String] The secret key used as the HMAC key.
  # @param length [Integer] The desired output length of each key in bytes.
  # @param algorithm [String, Symbol] The HMAC hash algorithm (e.g., `SHA256`, `SHA512`).
  # @param keys [Integer] The number of derived keys to generate (default: 1).
  # @param label [String] Optional label to distinguish different derivations.
  # @param context [String] Optional context to bind the key derivation to specific information.
  #
  # @return [Array<String>] Returns an array of derived keys.
  #
  # @raise [ArgumentError] If the requested length is invalid or the algorithm is unsupported.
  def self.counter_hmac(secret, length, algorithm, keys: 1, label: ''.b, context: ''.b)
    prf = -> (data) { OpenSSL::HMAC.digest(algorithm, secret, data) }
    counter(length, prf, keys: keys, label: label, context: context)
  end
end
