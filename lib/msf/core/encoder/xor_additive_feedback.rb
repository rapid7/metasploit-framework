# -*- coding: binary -*-
require 'msf/core'

###
#
# This class performs per-block XOR additive feedback encoding.
#
###
class Msf::Encoder::XorAdditiveFeedback < Msf::Encoder::Xor

  def initialize(info)
    super(info)
  end

  #
  # Encodes a block using the XOR additive feedback algorithm.
  #
  def encode_block(state, block)
    # XOR the key with the current block
    orig       = block.unpack(decoder_key_pack)[0]
    oblock     = orig ^ state.key

    # Add the original block contents to the key
    state.key  = (state.key + orig) % (1 << (decoder_key_size * 8))

    # Return the XOR'd block
    return [ oblock ].pack(decoder_key_pack)
  end

  #
  # Finds a key that is compatible with the badchars list.
  #
  def find_key(buf, badchars, state = Msf::EncoderState.new)
    key_bytes = integer_to_key_bytes(super(buf, badchars, nil))
    valid = false

    # Save the original key_bytes so we can tell if we loop around
    orig_key_bytes = key_bytes.dup

    # While we haven't found a valid key, keep trying the encode operation
    while (!valid)
      # Initialize the state back to defaults since we're trying to find a
      # key.
      init_state(state)

      begin
        # Reset the encoder state's key to the current set of key bytes
        state.reset(key_bytes_to_integer(key_bytes))

        # If the key itself contains a bad character, throw the bad
        # character exception with the index of the bad character in the
        # key.  Use a stub_size of zero to bypass the check to in the
        # rescue block.
        if ((idx = has_badchars?([state.key.to_i].pack(decoder_key_pack), badchars)) != nil)
          raise Msf::BadcharError.new(nil, idx, 0, nil)
        end

        # Perform the encode operation...if it encounters a bad character
        # an exception will be thrown
        valid = do_encode(state)
      rescue Msf::BadcharError => info
        # If the decoder stub contains a bad character, then there's not
        # much we can do about it
        if (info.index < info.stub_size)
          raise info, "The #{self.name} decoder stub contains a bad character.", caller
        end

        # Determine the actual index to the bad character inside the
        # encoded payload by removing the decoder stub from the index and
        # modulus off the decoder's key size
        idx = (info.index - info.stub_size) % (decoder_key_size)

        # Increment the key byte at the index that the bad character was
        # detected
        key_bytes[idx] = ((key_bytes[idx] + 1) % 255)

        # If we looped around, then give up.
        if (key_bytes[idx] == orig_key_bytes[idx])
          raise info, "The #{self.name} encoder failed to encode without bad characters.",
              caller
        end
      end
    end

    # Return the original key
    return state.orig_key
  end

end
