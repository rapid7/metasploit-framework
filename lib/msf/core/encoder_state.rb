###
#
# This class is used to track the state of a single encoding operation
# from start to finish.
#
###
class Msf::EncoderState

  #
  # Initializes a new encoder state, optionally with a key.
  #
  def initialize(key = nil)
    @orig_buf = nil
    @buf = nil
    reset(key)
  end

  #
  # Reset the encoder state by initializing the encoded buffer to an empty
  # string.
  #
  def reset(key = nil)
    init_key(key)

    self.encoded  = ''
  end

  #
  # Set the initial encoding key.
  #
  def init_key(key)
    self.key      = key
    self.orig_key = key
  end

  #
  # Set the raw buffer and the original buffer if one has not been set.
  #
  def buf=(buf)
    @orig_buf = buf if (@orig_buf == nil or @buf == nil)
    @buf = buf
  end

  attr_accessor :key # :nodoc:
  attr_accessor :orig_key # :nodoc:
  attr_reader   :buf # :nodoc:
  attr_reader   :orig_buf # :nodoc:
  attr_accessor :encoded # :nodoc:
  attr_accessor :context # :nodoc:
  attr_accessor :badchars # :nodoc:

  # A boolean that indicates whether context encoding is enabled
  attr_accessor :context_encoding
  # The address that contains they key on the target machine
  attr_accessor :context_address

  # Decoder settings
  attr_accessor :decoder_key_offset, :decoder_key_size, :decoder_key_pack # :nodoc:
  attr_accessor :decoder_stub # :nodoc:
end
