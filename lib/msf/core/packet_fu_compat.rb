# frozen_string_literal: true

require 'packetfu'

module Msf
  # PacketFu 2.0.0 derives field names from formatted backtraces, which changed
  # in Ruby 3.4. Use the structured method name until the dependency includes
  # https://github.com/packetfu/packetfu/pull/218, then remove this workaround.
  module PacketFuCompat
    # Converts a setter's input using the existing PacketFu field object.
    #
    # @param value [Object] input accepted by the PacketFu field's read method
    # @return [Object] the field returned by PacketFu after conversion
    def typecast(value)
      field = caller_locations(1, 1).first.base_label.delete_suffix('=')
      self[field.to_sym].read(value)
    end
  end
end

StructFu.prepend(Msf::PacketFuCompat)
