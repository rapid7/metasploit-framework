# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # Represents KerberosFlags.
        # https://www.rfc-editor.org/rfc/rfc4120.txt
        class KerberosFlags
          # @return [Integer] the integer value of the kerberos flags
          attr_reader :value

          # @param [Integer] value the numerical value of the flags
          # @raise [ArgumentError] if any of the parameters are of an invalid type
          def initialize(value)
            raise ArgumentError, 'Invalid value' unless value.is_a?(Integer)
            @value = value
          end

          # @param [Array<Integer,Rex::Proto::Kerberos::Model::KdcOptionFlags>] flags an array of numerical values representing flags
          # @return [Rex::Proto::Kerberos::Model::KdcOptionFlags]
          def self.from_flags(flags)
            value = 0
            flags.each do |flag|
              value |= 1 << (31 - flag)
            end

            new(value)
          end

          def to_i
            @value
          end

          # @param [Integer,Rex::Proto::Kerberos::Model::KdcOptionFlags] flag the numerical value of the flag to test for.
          # @return [Boolean] whether the flag is present within the current KdcOptionFlags
          def include?(flag)
            ((value >> (31 - flag)) & 1) == 1
          end

          # @return [Array<String>] The enabled flag names
          def enabled_flag_names
            sorted_flag_names = self.class.constants.sort_by { |name| self.class.const_get(name) }
            enabled_flag_names = sorted_flag_names.select { |flag| include?(self.class.const_get(flag)) }

            enabled_flag_names
          end

          def self.name(value)
            constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
          end

          # Override the equality test for KdcOptionFlags. Equality is
          # always tested against the #value of the KdcOptionFlags.
          #
          # @param other [Object] The object to test equality against
          # @raise [ArgumentError] if the other object is not either another KdcOptionFlags or a Integer
          # @return [Boolean] whether the equality test passed
          def ==(other)
            if other.is_a? self.class
              value == other.value
            elsif other.is_a? Integer
              value == other
            elsif other.nil?
              false
            else
              raise ArgumentError, "Cannot compare a #{self.class} to a #{other.class}"
            end
          end

          alias === ==
        end
      end
    end
  end
end
