# frozen_string_literal: true

require 'rex/proto/kerberos/credential_cache/krb5_ccache_presenter'
require 'rex/proto/kerberos/kerberos_readable_text_presenter'
require 'rex/proto/kerberos/kerberos_subscriber'
require 'rex/proto/kerberos/kerberos_trace_serializer'
require 'rex/proto/kerberos/service_authentication_trace_presenter'

module Rex
  module Proto
    module Kerberos
      # Logs Kerberos requests, responses, credentials, and service-authentication trace events.
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

        # @param logger [#print_line, #datastore]
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

        # (see Rex::Proto::Kerberos::KerberosSubscriber#on_ap_req)
        def on_ap_req(metadata)
          return unless service_authentication_trace_enabled?

          if trace_mode == TRACE_MODE_TICKET
            credential = metadata && metadata[:credential]
            return if credential.nil?

            print_credential_header('AP-REQ Selected Service Ticket')
            @logger.print_line(format_credential_for_trace_mode(credential))
            return
          end

          print_event('Kerberos AP-REQ', service_authentication_presenter.present_ap_req(metadata || {}), direction: :request)
        end

        # (see Rex::Proto::Kerberos::KerberosSubscriber#on_gss_token)
        def on_gss_token(metadata)
          return unless token_trace_enabled?

          print_event('Kerberos GSS Token', service_authentication_presenter.present_gss_token(metadata || {}), direction: :request)
        end

        # (see Rex::Proto::Kerberos::KerberosSubscriber#on_spnego_token)
        def on_spnego_token(metadata)
          return unless token_trace_enabled?

          print_event('Kerberos SPNEGO Token', service_authentication_presenter.present_spnego_token(metadata || {}), direction: :request)
        end

        # (see Rex::Proto::Kerberos::KerberosSubscriber#on_response_token)
        def on_response_token(metadata)
          return unless token_trace_enabled?

          print_event('Kerberos Response Token', service_authentication_presenter.present_response_token(metadata || {}), direction: :response)
        end

        # (see Rex::Proto::Kerberos::KerberosSubscriber#on_protocol_carrier)
        def on_protocol_carrier(metadata)
          return unless token_trace_enabled?

          title = metadata && metadata[:label] ? "Kerberos Carrier: #{metadata[:label]}" : 'Kerberos Carrier'
          direction = metadata && metadata[:direction].to_s == 'response' ? :response : :request
          print_event(title, service_authentication_presenter.present_protocol_carrier(metadata || {}), direction: direction)
        end

        private

        def message_trace_enabled?
          [TRACE_MODE_METADATA, TRACE_MODE_FULL].include?(trace_mode)
        end

        def credential_trace_enabled?
          [TRACE_MODE_METADATA, TRACE_MODE_TICKET, TRACE_MODE_FULL].include?(trace_mode)
        end

        def service_authentication_trace_enabled?
          [TRACE_MODE_METADATA, TRACE_MODE_TICKET, TRACE_MODE_FULL].include?(trace_mode)
        end

        def token_trace_enabled?
          [TRACE_MODE_METADATA, TRACE_MODE_FULL].include?(trace_mode)
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

        def print_event(title, body, direction:)
          request_color, response_color = trace_colors
          color = direction == :response ? response_color : request_color

          @logger.print_line('#' * 20)
          @logger.print_line("# #{title}")
          @logger.print_line('#' * 20)
          @logger.print_line("%clr#{color}#{body}%clr")
        end

        def message_type_name(message)
          msg_type = message.msg_type if message.respond_to?(:msg_type)
          return 'UNKNOWN' if msg_type.nil?

          name = trace_serializer.message_type_name(msg_type)
          name == 'UNKNOWN' ? "UNKNOWN (#{msg_type})" : name
        end

        def format_message_for_trace_mode(message)
          format_message(message, redact_binary: trace_mode != TRACE_MODE_FULL)
        end

        def format_message(message, redact_binary:)
          return 'null' if message.nil?

          if message.respond_to?(:attributes)
            readable_text_presenter.present(trace_serializer.serialize(message, redact_binary: redact_binary))
          else
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

        def ticket_presenter
          @ticket_presenter ||= Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter.new(nil)
        end

        def readable_text_presenter
          @readable_text_presenter ||= Rex::Proto::Kerberos::KerberosReadableTextPresenter.new
        end

        def trace_serializer
          @trace_serializer ||= Rex::Proto::Kerberos::KerberosTraceSerializer.new
        end

        def service_authentication_presenter
          @service_authentication_presenters ||= {}
          @service_authentication_presenters[trace_mode] ||= Rex::Proto::Kerberos::ServiceAuthenticationTracePresenter.new(
            trace_mode: trace_mode,
            serializer: trace_serializer,
            readable_text_presenter: readable_text_presenter
          )
        end

        def blank_value?(value)
          return true if value.nil? || value == false
          return value.strip.empty? if value.respond_to?(:strip)
          return value.empty? if value.respond_to?(:empty?)

          false
        end
      end
    end
  end
end
