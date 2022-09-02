# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # TODO: Consolidate this with KdcOptionFlags, almost identical bar from the class defining the flags
        # Represents the TicketFlags KerberosFlags.
        # https://www.rfc-editor.org/rfc/rfc4120.txt - TicketFlags     ::= KerberosFlags
        class TicketFlags
          # @return [Integer] the integer value of the kerberos flags
          attr_reader :value

          # @param [Integer] value the numerical value of the flags
          # @raise [ArgumentError] if any of the parameters are of an invalid type
          def initialize(value)
            raise ArgumentError, 'Invalid value' unless value.is_a?(Integer)

            @value = value
          end

          # @param [Array<Integer,Rex::Proto::Kerberos::Model::TicketFlag>] flags an array of numerical values representing flags
          # @return [Rex::Proto::Kerberos::Model::TicketFlags]
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

          # @param [Integer,Rex::Proto::Kerberos::Model::TicketFlag] flag the numerical value of the flag to test for.
          # @return [Boolean] whether the flag is present within the current TicketFlags
          def include?(flag)
            ((value >> (31 - flag)) & 1) == 1
          end

          # @return [Boolean] whether the flag is present within the current TicketFlags
          def enabled_flag_names
            sorted_flag_names = TicketFlag.constants.sort_by { |name| TicketFlag.const_get(name) }
            enabled_flag_names = sorted_flag_names.select { |flag| include?(TicketFlag.const_get(flag)) }

            enabled_flag_names
          end

          # Override the equality test for TicketFlags. Equality is
          # always tested against the #value of the TicketFlags.
          #
          # @param [Object] other_object the object to test equality against
          # @raise [ArgumentError] if the other object is not either another TicketFlags or a Integer
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
