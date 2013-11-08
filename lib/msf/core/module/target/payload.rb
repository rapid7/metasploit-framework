# Target-specific payload modifications
module Msf::Module::Target::Payload
  #
  # The bad characters specific to this target for the payload.
  #
  def payload_badchars
    opts['Payload'] ? opts['Payload']['BadChars'] : nil
  end

  #
  # Payload prepend information for this target.
  #
  def payload_prepend
    opts['Payload'] ? opts['Payload']['Prepend'] : nil
  end

  #
  # Payload append information for this target.
  #
  def payload_append
    opts['Payload'] ? opts['Payload']['Append'] : nil
  end

  #
  # Payload prepend encoder information for this target.
  #
  def payload_prepend_encoder
    opts['Payload'] ? opts['Payload']['PrependEncoder'] : nil
  end

  #
  # Payload stack adjustment information for this target.
  #
  def payload_stack_adjustment
    opts['Payload'] ? opts['Payload']['StackAdjustment'] : nil
  end

  #
  # Payload max nops information for this target.
  #
  def payload_max_nops
    opts['Payload'] ? opts['Payload']['MaxNops'] : nil
  end

  #
  # Payload min nops information for this target.
  #
  def payload_min_nops
    opts['Payload'] ? opts['Payload']['MinNops'] : nil
  end

  #
  # Payload space information for this target.
  #
  def payload_space
    opts['Payload'] ? opts['Payload']['Space'] : nil
  end

  #
  # The payload encoder type or types that can be used when generating the
  # encoded payload (such as alphanum, unicode, xor, and so on).
  #
  def payload_encoder_type
    opts['Payload'] ? opts['Payload']['EncoderType'] : nil
  end

  #
  # A hash of options that be initialized in the select encoder's datastore
  # that may be required as parameters for the encoding operation.  This is
  # particularly useful when a specific encoder type is being used (as
  # specified by the EncoderType hash element).
  #
  def payload_encoder_options
    opts['Payload'] ? opts['Payload']['EncoderOptions'] : nil
  end

  #
  # Returns a hash of extended options that are applicable to payloads used
  # against this particular target.
  #
  def payload_extended_options
    opts['Payload'] ? opts['Payload']['ExtendedOptions'] : nil
  end
end