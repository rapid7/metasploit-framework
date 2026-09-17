# frozen_string_literal: true

require 'set'
require 'time'
require 'rex/proto/kerberos/crypto'
require 'rex/proto/kerberos/model'

module Rex
  module Proto
    module Kerberos
      # Serializes Kerberos models into trace-friendly primitive values.
      class KerberosTraceSerializer
        # @param element [Object] a Kerberos model object
        # @param redact_binary [Boolean] whether binary values should omit their contents
        # @return [Hash]
        def serialize(element, redact_binary:)
          element.attributes.each_with_object({}) do |attribute, output|
            value = element.public_send(attribute)
            next if value.nil?

            output[serialized_attribute_key(element, attribute)] = serialize_value(
              value,
              element: element,
              attribute: attribute.to_sym,
              redact_binary: redact_binary
            )
          end
        end

        # @param value [Object]
        # @param redact_binary [Boolean]
        # @param element [Object, nil]
        # @param attribute [Symbol, nil]
        # @return [Object]
        def serialize_value(value, redact_binary:, element: nil, attribute: nil)
          if value.respond_to?(:attributes)
            serialize(value, redact_binary: redact_binary)
          elsif kerberos_error_code?(value)
            {
              'name' => value.name,
              'value' => value.value,
              'description' => value.description
            }
          else
            serialize_scalar_value(value, element: element, attribute: attribute, redact_binary: redact_binary)
          end
        end

        # @param msg_type [Integer]
        # @return [String]
        def message_type_name(msg_type)
          case msg_type
          when Rex::Proto::Kerberos::Model::AS_REQ
            'AS-REQ'
          when Rex::Proto::Kerberos::Model::AS_REP
            'AS-REP'
          when Rex::Proto::Kerberos::Model::TGS_REQ
            'TGS-REQ'
          when Rex::Proto::Kerberos::Model::TGS_REP
            'TGS-REP'
          when Rex::Proto::Kerberos::Model::AP_REQ
            'AP-REQ'
          when Rex::Proto::Kerberos::Model::AP_REP
            'AP-REP'
          when Rex::Proto::Kerberos::Model::KRB_ERROR
            'KRB-ERROR'
          else
            'UNKNOWN'
          end
        end

        # @param value [Integer]
        # @return [String]
        def encryption_type_name(value)
          Rex::Proto::Kerberos::Crypto::Encryption.const_name(value) || 'UNKNOWN'
        end

        private

        def serialized_attribute_key(element, attribute)
          if attribute == :options && element.is_a?(Rex::Proto::Kerberos::Model::ApReq)
            'ap_options'
          elsif attribute == :options && element.is_a?(Rex::Proto::Kerberos::Model::KdcRequestBody)
            'kdc_options'
          else
            attribute.to_s
          end
        end

        def serialize_scalar_value(value, redact_binary:, element: nil, attribute: nil)
          case value
          when Array
            value.map { |entry| serialize_value(entry, element: element, attribute: attribute, redact_binary: redact_binary) }
          when Set
            value.to_a.map { |entry| serialize_value(entry, element: element, attribute: attribute, redact_binary: redact_binary) }
          when Hash
            value.each_with_object({}) do |(key, entry), output|
              output[key.to_s] = serialize_value(entry, redact_binary: redact_binary)
            end
          when Rex::Proto::Kerberos::Model::KerberosFlags
            {
              'value' => value.to_i,
              'flags' => value.enabled_flag_names.map(&:to_s)
            }
          when Time
            value.utc.iso8601
          when String
            serialize_string(value, redact_binary: redact_binary)
          when Symbol
            value.to_s
          when Integer
            serialize_enum_value(value, element: element, attribute: attribute) || value
          when Float, TrueClass, FalseClass, NilClass
            value
          else
            value.to_s
          end
        end

        def serialize_enum_value(value, element:, attribute:)
          enum_name = case attribute
                      when :msg_type
                        message_type_name(value)
                      when :type
                        enum_type_name(value, element)
                      when :etype
                        encryption_type_name(value)
                      when :name_type
                        enum_name_type_name(value, element)
                      end
          return nil if enum_name.nil?

          "#{value} (#{enum_name})"
        end

        def enum_type_name(value, element)
          if element.is_a?(Rex::Proto::Kerberos::Model::PreAuthDataEntry)
            const_name_for_value(Rex::Proto::Kerberos::Model::PreAuthType, value)
          elsif element.is_a?(Rex::Proto::Kerberos::Model::EncryptionKey)
            encryption_type_name(value)
          end
        end

        def enum_name_type_name(value, element)
          return nil unless element.is_a?(Rex::Proto::Kerberos::Model::PrincipalName)

          const_name_for_value(Rex::Proto::Kerberos::Model::NameType, value)
        end

        def const_name_for_value(mod, value)
          mod.constants.each do |const_name|
            return const_name.to_s if mod.const_get(const_name) == value
          rescue StandardError
            next
          end

          'UNKNOWN'
        end

        def kerberos_error_code?(value)
          value.respond_to?(:name) && value.respond_to?(:value) && value.respond_to?(:description)
        end

        def serialize_string(value, redact_binary:)
          return value if printable_string?(value)
          return "[binary #{value.bytesize} bytes]" if redact_binary

          "[binary #{value.bytesize} bytes: #{value.unpack1('H*')}]"
        end

        def printable_string?(value)
          utf8_value = value.dup.force_encoding(::Encoding::UTF_8)
          utf8_value.valid_encoding? && utf8_value.match?(/\A[[:print:]\r\n\t ]*\z/)
        rescue ::Encoding::CompatibilityError
          false
        end
      end
    end
  end
end
