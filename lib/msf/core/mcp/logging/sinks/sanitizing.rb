# frozen_string_literal: true

require 'rex/logging/log_sink'

module Msf::MCP
  module Logging
    module Sinks
      # A Rex LogSink decorator that redacts sensitive information from log
      # messages before delegating to a wrapped sink.
      #
      # @example Wrapping a JsonFlatfile sink
      #   inner = Msf::MCP::Logging::Sinks::JsonFlatfile.new('msfmcp.log')
      #   sink  = Msf::MCP::Logging::Sinks::Sanitizing.new(inner)
      #   register_log_source('mcp', sink, Rex::Logging::LEV_0)
      class Sanitizing
        include Rex::Logging::LogSink

        REDACTED = '[REDACTED]'

        SENSITIVE_PATTERNS = {
          password:     /password[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          token_keyval: /token[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          token_header: /token\s+[a-zA-Z0-9_\-\.]+/i,
          api_key:      /api[_-]?key[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          secret:       /secret[_-]?key[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          credential:   /credential[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          auth:         /auth[\"']?\s*[:=]\s*[\"']?[^\"',\s}]+/i,
          bearer:       /bearer\s+[a-zA-Z0-9_\-\.]+/i
        }.freeze

        SENSITIVE_KEYS = /\A(password|token|secret|api_key|api_secret|credential|auth_token|bearer|access_token|private_key)\z/i

        # @param sink [Rex::Logging::LogSink] The underlying sink to write to
        def initialize(sink)
          @sink = sink
        end

        def log(sev, src, level, msg)
          @sink.log(sev, src, level, sanitize(msg))
        end

        def cleanup
          @sink.cleanup
        end

        private

        # Sanitize data for logging by redacting sensitive information.
        #
        # @param data [Object] Data to sanitize (Hash, Array, String, or other)
        # @return [Object] Sanitized copy of data
        def sanitize(data)
          case data
          when Hash
            data.each_with_object({}) do |(k, v), result|
              result[k] = if k.to_s.match?(SENSITIVE_KEYS)
                            v.is_a?(Hash) || v.is_a?(Array) ? sanitize(v) : REDACTED
                          elsif k.to_sym == :exception && v.is_a?(Exception)
                            ex_msg = { class: v.class.name, message: sanitize(v.message) }
                            if get_log_level(LOG_SOURCE) >= BACKTRACE_LOG_LEVEL
                              bt = v.backtrace&.first(5) || []
                              bt = bt.map{|x| x.sub(/^.*lib\//, 'lib/') } # Dont expose the install path
                              ex_msg[:backtrace] = sanitize(bt)
                            end
                            ex_msg
                          else
                            sanitize(v)
                          end
            end
          when Array
            data.map { |item| sanitize(item) }
          when String
            sanitize_string(data)
          else
            data
          end
        end

        # Sanitize a string by redacting sensitive patterns
        #
        # @param str [String] String to sanitize
        # @return [String] Sanitized string
        def sanitize_string(str)
          return str unless str.is_a?(String)

          sanitized = str.dup

          # Redact sensitive patterns - match entire pattern and replace value part
          SENSITIVE_PATTERNS.each do |name, pattern|
            sanitized = sanitized.gsub(pattern) do |match|
              # For header-style tokens (token abc123, bearer abc123), replace the value
              # # TODO: check this
              if name == :token_header || name == :bearer
                parts = match.split(/\s+/, 2)
                "#{parts[0]} #{REDACTED}"
              # For key-value style (token: abc123, password=abc123), replace after separator
              elsif match =~ /(.*[:=])\s*[\"']?/
                "#{Regexp.last_match[1]} #{REDACTED}"
              else
                REDACTED
              end
            end
          end

          sanitized
        end

      end
    end
  end
end
