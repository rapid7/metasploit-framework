module Net; module SSH; module Transport

  # A cipher that does nothing but pass the data through, unchanged. This
  # keeps things in the code nice and clean when a cipher has not yet been
  # determined (i.e., during key exchange).
  class IdentityCipher
    class <<self
      # A default block size of 8 is required by the SSH2 protocol.
      def block_size
        8
      end

      # Returns an arbitrary integer.
      def iv_len
        4
      end

      # Does nothing. Returns self.
      def encrypt
        self
      end

      # Does nothing. Returns self.
      def decrypt
        self
      end

      # Passes its single argument through unchanged.
      def update(text)
        text
      end

      # Returns the empty string.
      def final
        ""
      end

      # The name of this cipher, which is "identity".
      def name
        "identity"
      end

      # Does nothing. Returns nil.
      def iv=(v)
        nil
      end

      # Does nothing. Returns self.
      def reset
        self
      end
    end
  end

end; end; end
