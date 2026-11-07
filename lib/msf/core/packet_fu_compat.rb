# frozen_string_literal: true

module Msf
  # Compatibility layer for PacketFu 2.0.0 on Ruby 3.4 and newer.
  #
  # StructFu#typecast determines which attribute is being assigned by
  # regex-parsing the immediate caller backtrace frame for the pre-Ruby-3.4
  # format, +path:line:in `attr='+. Ruby 3.4 changed backtrace formatting to
  # use a leading single quote and qualified method names,
  # (+path:line:in 'Class#attr='+), so the original expression no longer
  # matches and every packet header setter fails with
  # +NoMethodError (undefined method '[]' for nil)+.
  #
  # {Msf::PacketFuCompat.apply!} redefines +StructFu#typecast+ to understand
  # both formats and to raise an informative error when a frame cannot be
  # parsed. This module can be removed once the framework depends on a
  # PacketFu release containing an upstream fix (packetfu/packetfu#218).
  module PacketFuCompat
    # Matches setter names in both pre-3.4 (+in `attr='+) and 3.4+
    # (+in 'Namespace::Class#attr='+) backtrace frames.
    SETTER_FRAME = /in [`'](?:(?:\w+(?:::\w+)*)(?:#|\.))?(\w+)='/.freeze

    class << self
      # Patches +StructFu#typecast+ unless it has already been patched.
      #
      # @return [Boolean] true if the patch was applied, false if it was
      #   already in place
      def apply!
        return false if ::StructFu.instance_variable_defined?(:@msf_typecast_compat)

        # NOTE: ::Module must be fully qualified - inside the Msf namespace the
        # bare +Module+ constant would resolve to +Msf::Module+.
        compat = ::Module.new do
          def typecast(input)
            setter = caller(1).lazy.map { |frame| frame.match(Msf::PacketFuCompat::SETTER_FRAME) }.compact.first

            unless setter
              raise NameError,
                    'StructFu#typecast could not determine the attribute being set'
            end

            self[setter[1].to_sym].read(input)
          end
        end

        ::StructFu.prepend(compat)
        ::StructFu.instance_variable_set(:@msf_typecast_compat, true)
        true
      end
    end
  end
end
