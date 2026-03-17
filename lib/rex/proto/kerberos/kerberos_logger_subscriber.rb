# -*- coding: binary -*-

require 'rex/proto/kerberos/kerberos_subscriber'
require 'rex/proto/kerberos/model'

module Rex
  module Proto
    module Kerberos
      # Formats Kerberos request and response events for console tracing.
      class KerberosLoggerSubscriber < KerberosSubscriber
        RAW_PREVIEW_BYTES = 32

        MESSAGE_TYPES = {
          Rex::Proto::Kerberos::Model::AS_REQ => 'AS-REQ',
          Rex::Proto::Kerberos::Model::AS_REP => 'AS-REP',
          Rex::Proto::Kerberos::Model::TGS_REQ => 'TGS-REQ',
          Rex::Proto::Kerberos::Model::TGS_REP => 'TGS-REP',
          Rex::Proto::Kerberos::Model::KRB_ERROR => 'KRB-ERROR',
          Rex::Proto::Kerberos::Model::AP_REQ => 'AP-REQ',
          Rex::Proto::Kerberos::Model::AP_REP => 'AP-REP'
        }.freeze

        def initialize(logger:)
          super()
          raise 'Incompatible logger' unless logger.respond_to?(:print_line) && logger.respond_to?(:datastore)

          @logger = logger
        end

        def on_request(request, raw: nil, context: {})
          return unless trace_enabled?

          @logger.print_line('#' * 20)
          @logger.print_line('# Kerberos Request:')
          @logger.print_line('#' * 20)
          @logger.print_line(request_summary(request, context))
          request_details(request).each { |line| @logger.print_line(line) }
          raw_details(raw).each { |line| @logger.print_line(line) }
        end

        def on_response(response, raw: nil, context: {})
          return unless trace_enabled?

          @logger.print_line('#' * 20)
          @logger.print_line('# Kerberos Response:')
          @logger.print_line('#' * 20)
          @logger.print_line(response_summary(response, context))
          response_details(response).each { |line| @logger.print_line(line) }
          raw_details(raw).each { |line| @logger.print_line(line) }
        end

        private

        def trace_enabled?
          @logger.datastore['KerberosTicketTrace']
        end

        def trace_level
          level = @logger.datastore['KerberosTicketTraceLevel'].to_s.downcase
          return 'summary' if level.empty?
          return level if %w[summary raw].include?(level)

          'summary'
        end

        def raw_level?
          trace_level == 'raw'
        end

        def request_summary(request, context)
          body = request.req_body
          parts = []
          parts << "peer=#{context[:peer]}" if context[:peer]
          parts << "msg=#{message_name(request.msg_type)}"
          parts << "realm=#{body.realm}" if body&.realm
          parts << "cname=#{principal_name(body&.cname)}" if body&.cname
          parts << "sname=#{principal_name(body&.sname)}" if body&.sname
          parts.join(' ')
        end

        def request_details(request)
          return [] unless raw_level?

          body = request.req_body
          detail = []
          detail << "pvno=#{request.pvno}"
          detail << "msg_type=#{request.msg_type}"
          detail << "pa_data_count=#{Array(request.pa_data).length}"
          detail << "etypes=#{body.etype.join(',')}" if body&.etype&.any?
          [detail.join(' ')]
        end

        def response_summary(response, context)
          parts = []
          parts << "peer=#{context[:peer]}" if context[:peer]

          case response
          when Rex::Proto::Kerberos::Model::KrbError
            parts << "msg=#{message_name(response.msg_type)}"
            parts << "realm=#{response.realm}" if response.realm
            parts << "cname=#{principal_name(response.cname)}" if response.cname
            parts << "sname=#{principal_name(response.sname)}" if response.sname
            parts << "error=#{response.error_code.name}(#{response.error_code.value})" if response.error_code
          when Rex::Proto::Kerberos::Model::KdcResponse
            parts << "msg=#{message_name(response.msg_type)}"
            parts << "realm=#{response.crealm}" if response.crealm
            parts << "cname=#{principal_name(response.cname)}" if response.cname
            ticket_sname = response.ticket&.sname
            parts << "sname=#{principal_name(ticket_sname)}" if ticket_sname
          when Rex::Proto::Kerberos::Model::ApRep
            parts << "msg=#{message_name(response.msg_type)}"
          else
            parts << 'response=nil'
          end

          parts.join(' ')
        end

        def response_details(response)
          return [] unless raw_level?

          detail = []

          case response
          when Rex::Proto::Kerberos::Model::KrbError
            detail << "pvno=#{response.pvno}"
            detail << "msg_type=#{response.msg_type}"
            detail << "server_time=#{response.stime.utc.iso8601}" if response.stime
            detail << "e_data_present=#{!response.e_data.nil?}"
          when Rex::Proto::Kerberos::Model::KdcResponse
            detail << "pvno=#{response.pvno}"
            detail << "msg_type=#{response.msg_type}"
            detail << "pa_data_count=#{Array(response.pa_data).length}"
          when Rex::Proto::Kerberos::Model::ApRep
            detail << "pvno=#{response.pvno}"
            detail << "msg_type=#{response.msg_type}"
          else
            return []
          end

          [detail.join(' ')]
        end

        def raw_details(raw)
          return [] unless raw_level? && raw

          preview = raw.to_s.b.bytes.first(RAW_PREVIEW_BYTES).map { |byte| format('%02x', byte) }.join(' ')
          suffix = raw.to_s.b.length > RAW_PREVIEW_BYTES ? ' ...' : ''

          [
            "raw_length=#{raw.to_s.b.length}",
            "raw_preview=#{preview}#{suffix}"
          ]
        end

        def principal_name(principal)
          principal&.to_s
        end

        def message_name(message_type)
          MESSAGE_TYPES.fetch(message_type, "UNKNOWN(#{message_type})")
        end
      end
    end
  end
end
