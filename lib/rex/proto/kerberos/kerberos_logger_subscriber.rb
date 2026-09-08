# -*- coding: binary -*-

require 'set'
require 'time'
require 'rex/proto/kerberos/model'
require 'rex/proto/kerberos/crypto'
require 'rex/proto/kerberos/kerberos_subscriber'
require 'rex/proto/kerberos/kerberos_readable_text_presenter'
require 'rex/proto/kerberos/credential_cache/krb5_ccache_presenter'

module Rex
  module Proto
    module Kerberos
      # Logs Kerberos requests/responses
      class KerberosLoggerSubscriber < KerberosSubscriber
        TRACE_MODE_OFF = 'off'
        TRACE_MODE_METADATA = 'metadata'
        TRACE_MODE_TICKET = 'ticket'
        TRACE_MODE_FULL = 'full'
        TRACE_MODES = [
          TRACE_MODE_OFF,
          TRACE_MODE_METADATA,
          TRACE_MODE_TICKET,
          TRACE_MODE_FULL
        ].freeze

        def initialize(logger:)
          super()
          raise 'Incompatible logger' unless logger.respond_to?(:print_line) && logger.respond_to?(:datastore)

          @logger = logger
        end

        # (see Rex::Proto::Kerberos::KerberosSubscriber#on_request)
        def on_request(request)
          return unless message_trace_enabled?

          request_color, _response_color = trace_colors
          print_header('Request', request)
          @logger.print_line("%clr#{request_color}#{format_message_for_trace_mode(request)}%clr")
        end

        # (see Rex::Proto::Kerberos::KerberosSubscriber#on_response)
        def on_response(response)
          return unless message_trace_enabled?

          _request_color, response_color = trace_colors
          print_header('Response', response)
          if response.nil?
            @logger.print_line('No response received')
            return
          end

          @logger.print_line("%clr#{response_color}#{format_message_for_trace_mode(response)}%clr")
        end

        # (see Rex::Proto::Kerberos::KerberosSubscriber#on_credential)
        def on_credential(credential, source: nil)
          return unless credential_trace_enabled?
          return if credential.nil?

          print_credential_header(source)
          @logger.print_line(format_credential_for_trace_mode(credential))
        end

        private

        def message_trace_enabled?
          [TRACE_MODE_METADATA, TRACE_MODE_FULL].include?(trace_mode)
        end

        def credential_trace_enabled?
          [TRACE_MODE_METADATA, TRACE_MODE_TICKET, TRACE_MODE_FULL].include?(trace_mode)
        end

        def trace_mode
          configured_trace_mode = @logger.datastore['KerberosTicketTrace']
          return TRACE_MODE_FULL if configured_trace_mode == true
          return TRACE_MODE_OFF if blank_value?(configured_trace_mode)

          normalized_trace_mode = configured_trace_mode.to_s.downcase
          TRACE_MODES.include?(normalized_trace_mode) ? normalized_trace_mode : TRACE_MODE_OFF
        end

        def trace_colors
          configured_trace_colors = @logger.datastore['KerberosTicketTraceColors']
          # Keep HttpTrace-compatible default formatting: request/response color pair.
          trace_colors = blank_value?(configured_trace_colors) ? 'red/blu' : configured_trace_colors
          trace_colors += '/' if trace_colors.count('/') == 0
          trace_colors.gsub('/', ' / ').split('/').map do |color|
            blank_value?(color&.strip) ? '' : "%bld%#{color.strip}"
          end
        end

        def print_header(direction, message)
          @logger.print_line('#' * 20)
          @logger.print_line("# Kerberos #{direction}: #{message_type_name(message)}")
          @logger.print_line('#' * 20)
        end

        def print_credential_header(source)
          @logger.print_line('#' * 20)
          @logger.print_line("# Kerberos Credential#{source ? ": #{source}" : ''}")
          @logger.print_line('#' * 20)
        end

        def message_type_name(message)
          msg_type = message.msg_type if message.respond_to?(:msg_type)
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
          when nil
            'UNKNOWN'
          else
            "UNKNOWN (#{msg_type})"
          end
        end

        def format_message_for_trace_mode(message)
          format_message(message, redact_binary: trace_mode != TRACE_MODE_FULL)
        end

        def format_message(message, redact_binary:)
          return 'null' if message.nil?

          if message.respond_to?(:attributes)
            serialized_message = serialize_element(message, redact_binary: redact_binary)
            readable_text_presenter.present(serialized_message)
          else
            # Fall back for non-model objects.
            message.to_s
          end
        rescue StandardError => e
          "Kerberos trace rendering error: #{e.class}: #{e.message}"
        end

        def format_credential_for_trace_mode(credential)
          ticket_presenter.present_credentials([credential], trace_mode: trace_mode)
        rescue StandardError => e
          "Credential presenter error: #{e.class}: #{e.message}"
        end

        def serialize_element(element, redact_binary:)
          element.attributes.each_with_object({}) do |attribute, output|
            value = element.public_send(attribute)
            next if value.nil?

            output[serialized_attribute_key(element, attribute)] = serialize_value(value, element: element, attribute: attribute.to_sym, redact_binary: redact_binary)
          end
        end

        def serialized_attribute_key(element, attribute)
          if attribute == :options && element.is_a?(Rex::Proto::Kerberos::Model::ApReq)
            'ap_options'
          elsif attribute == :options && element.is_a?(Rex::Proto::Kerberos::Model::KdcRequestBody)
            'kdc_options'
          else
            attribute.to_s
          end
        end

        def serialize_value(value, redact_binary:, element: nil, attribute: nil)
          if value.respond_to?(:attributes)
            # Recursively serialize nested Kerberos model objects.
            serialize_element(value, redact_binary: redact_binary)
          elsif kerberos_error_code?(value)
            # Normalize ErrorCode-like objects to a compact structured form.
            {
              'name' => value.name,
              'value' => value.value,
              'description' => value.description
            }
          else
            serialize_scalar_value(value, element: element, attribute: attribute, redact_binary: redact_binary)
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
                        message_type_name_for_value(value)
                      when :type
                        enum_type_name(value, element)
                      when :etype
                        enum_etype_name(value)
                      when :name_type
                        enum_name_type_name(value, element)
                      end
          return nil if enum_name.nil?

          "#{value} (#{enum_name})"
        end

        def message_type_name_for_value(msg_type)
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

        def enum_type_name(value, element)
          if element.is_a?(Rex::Proto::Kerberos::Model::PreAuthDataEntry)
            const_name_for_value(Rex::Proto::Kerberos::Model::PreAuthType, value)
          elsif element.is_a?(Rex::Proto::Kerberos::Model::EncryptionKey)
            enum_etype_name(value)
          end
        end

        def enum_etype_name(value)
          Rex::Proto::Kerberos::Crypto::Encryption.const_name(value) || 'UNKNOWN'
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

        def present_time(time)
          time.localtime.to_s
        end

        def ticket_presenter
          @ticket_presenter ||= Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter.new(nil)
        end

        def readable_text_presenter
          @readable_text_presenter ||= Rex::Proto::Kerberos::KerberosReadableTextPresenter.new
        end

        def printable_string?(value)
          utf8_value = value.dup.force_encoding(::Encoding::UTF_8)
          utf8_value.valid_encoding? && utf8_value.match?(/\A[[:print:]\r\n\t ]*\z/)
        rescue ::Encoding::CompatibilityError
          false
        end

        def blank_value?(value)
          # Avoid depending on ActiveSupport's `blank?` for this Rex-level helper.
          return true if value.nil? || value == false
          return value.strip.empty? if value.respond_to?(:strip)
          return value.empty? if value.respond_to?(:empty?)

          false
        end
      end
    end
  end
end
