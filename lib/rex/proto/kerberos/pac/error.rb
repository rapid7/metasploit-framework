# frozen_string_literal: true

module Rex
  module Proto
    module Kerberos
      module Pac
        module Error
          # Generic Pac Error
          class PacError < StandardError
            def initialize(msg = 'Invalid PAC')
              super
            end
          end

          # To be raised when a PAC object does not contain one or more specific Info Buffers
          class MissingInfoBuffer < PacError

            # @return [Array<Integer>] The ul types of the missing info buffers
            attr_accessor :ul_types

            # @param [String, nil] msg
            # @param [Array<Integer>] ul_types The ul types of the missing info buffers.
            def initialize(msg = nil, ul_types:)
              @ul_types = ul_types
              super(msg || generate_message)
            end

            # @return [String] A message created containing the names of the missing buffers.
            def generate_message
              missing_buffer_names = @ul_types.map do |ul_type|
                Rex::Proto::Kerberos::Pac::Krb5PacElementType.const_name(ul_type)
              end
              "Missing Info Buffer(s): #{missing_buffer_names.join(', ')}"
            end
          end
        end
      end
    end
  end
end
