# -*- coding: binary -*-

require 'json'
require 'set'
require 'time'
require 'rex/proto/kerberos/model'
require 'rex/proto/kerberos/kerberos_subscriber'
require 'rex/proto/kerberos/credential_cache/krb5_ccache_presenter'

module Rex
module Proto
module Kerberos

  # Logs Kerberos requests/responses
  class KerberosLoggerSubscriber < KerberosSubscriber
    def initialize(logger:)
      super()
      raise RuntimeError, "Incompatible logger" unless logger.respond_to?(:print_line) && logger.respond_to?(:datastore)
      @logger = logger
    end

    # (see Rex::Proto::Kerberos::KerberosSubscriber#on_request)
    def on_request(request)
      return unless trace_enabled?

      request_color, _response_color = trace_colors
      print_header('Request', request)
      @logger.print_line("%clr#{request_color}#{format_message(request)}%clr")
    end

    # (see Rex::Proto::Kerberos::KerberosSubscriber#on_response)
    def on_response(response)
      return unless trace_enabled?

      _request_color, response_color = trace_colors
      print_header('Response', response)
      if response.nil?
        @logger.print_line('No response received')
        return
      end

      @logger.print_line("%clr#{response_color}#{format_message(response)}%clr")
    end

    # (see Rex::Proto::Kerberos::KerberosSubscriber#on_credential)
    def on_credential(credential, source: nil)
      return unless trace_enabled?
      return if credential.nil?

      print_credential_header(source)
      @logger.print_line(format_credential(credential))
    end

    private

    def trace_enabled?
      @logger.datastore['KerberosTicketTrace']
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

    def format_message(message)
      return 'null' if message.nil?

      if message.respond_to?(:attributes)
        # Kerberos model objects are serialized into stable JSON for easier diffing/debugging.
        JSON.pretty_generate(serialize_element(message))
      else
        # Fall back for non-model objects.
        message.to_s
      end
    end

    def format_credential(credential)
      rendered_credential = ticket_presenter.present_cred(credential)
      [
        'Creds: 1',
        "  Credential[0]:\n#{rendered_credential.indent(4)}"
      ].join("\n")
    rescue StandardError => e
      "Credential presenter error: #{e.class}: #{e.message}"
    end

    def serialize_element(element)
      element.attributes.each_with_object({}) do |attribute, output|
        value = element.public_send(attribute)
        next if value.nil?

        output[attribute.to_s] = serialize_value(value)
      end
    end

    def serialize_value(value)
      if value.respond_to?(:attributes)
        # Recursively serialize nested Kerberos model objects.
        serialize_element(value)
      elsif kerberos_error_code?(value)
        # Normalize ErrorCode-like objects to a compact structured form.
        {
          'name' => value.name,
          'value' => value.value,
          'description' => value.description
        }
      else
        serialize_scalar_value(value)
      end
    end

    def serialize_scalar_value(value)
      case value
      when Array
        value.map { |entry| serialize_value(entry) }
      when Set
        value.to_a.map { |entry| serialize_value(entry) }
      when Hash
        value.each_with_object({}) do |(key, entry), output|
          output[key.to_s] = serialize_value(entry)
        end
      when Rex::Proto::Kerberos::Model::KerberosFlags
        {
          'value' => value.to_i,
          'flags' => value.enabled_flag_names.map(&:to_s)
        }
      when Time
        value.utc.iso8601
      when String
        serialize_string(value)
      when Symbol
        value.to_s
      when Integer, Float, TrueClass, FalseClass, NilClass
        value
      else
        value.to_s
      end
    end

    def kerberos_error_code?(value)
      value.respond_to?(:name) && value.respond_to?(:value) && value.respond_to?(:description)
    end

    def serialize_string(value)
      return value if printable_string?(value)

      # Expand binary/non-printable strings fully in hex.
      "[binary #{value.bytesize} bytes: #{value.unpack1('H*')}]"
    end

    def ticket_presenter
      @ticket_presenter ||= Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter.new(nil)
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
