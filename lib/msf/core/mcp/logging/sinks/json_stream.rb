# frozen_string_literal: true

module Msf::MCP
  module Logging
    module Sinks
      # A Rex LogSink that formats log messages as JSON and writes them to
      # an IO stream (e.g. $stdout, a File, a StringIO).
      #
      # @example Writing JSON logs to $stderr
      #   sink = Msf::MCP::Logging::Sinks::JsonStream.new($stderr)
      #   register_log_source('mcp', sink, Rex::Logging::LEV_0)
      #
      # @example Backed by a file via JsonFlatfile
      #   sink = Msf::MCP::Logging::Sinks::JsonFlatfile.new('msfmcp.log')
      #   register_log_source('mcp', sink, Rex::Logging::LEV_0)
      class JsonStream
        include Rex::Logging::LogSink

        def initialize(stream)
          @stream = stream
        end

        def log(sev, src, level, msg)
          log_entry = {
            timestamp: get_current_timestamp,
            severity: sev.to_s.upcase,
            level: level.to_s,
            source: src.to_s,
            message: msg.to_s
          }

          if msg.is_a?(Hash)
            log_entry[:message] = msg[:message] if msg[:message] && !msg[:message].empty?
            if msg[:context] && !msg[:context].empty?
              log_entry[:context] = if debug_log_level?
                                      msg[:context]
                                    else
                                      summarize_context(msg[:context])
                                    end
            end
            if msg[:exception]
              log_entry[:exception] = if msg[:exception].is_a?(Exception)
                                        ex_msg = { class: msg[:exception].class.name, message: msg[:exception].message }
                                        if get_log_level(LOG_SOURCE) >= BACKTRACE_LOG_LEVEL
                                          ex_msg[:backtrace] = msg[:exception].backtrace&.first(5) || []
                                        end
                                        ex_msg
                                      else
                                        msg[:exception]
                                      end
            end
          end

          stream.write(log_entry.to_json + "\n")
          stream.flush
        end

        def cleanup
          stream.close
        end

        protected

        attr_accessor :stream

        private

        # Keys whose values can be large (full API responses, tool results, etc.)
        # and should be truncated at non-DEBUG log levels.
        HEAVY_KEYS = %i[result body error].freeze

        # Maximum character length for truncated values.
        TRUNCATE_MAX_LENGTH = 1000

        # Whether the current log level for the MCP source is at least DEBUG
        # (LEV_3 / BACKTRACE_LOG_LEVEL), which enables full context output
        # and exception backtraces.
        #
        # @return [Boolean]
        def debug_log_level?
          get_log_level(LOG_SOURCE) >= BACKTRACE_LOG_LEVEL
        end

        # Return a reduced copy of +ctx+ suitable for non-DEBUG log entries.
        #
        # Heavy keys (:result, :body, :error) are truncated. The :response sub-hash is also
        # truncated. All other keys (scalars like :method, :elapsed_ms, :session_id) pass
        # through unchanged.
        #
        # @param ctx [Hash] The original context hash
        # @return [Hash] A summarized copy
        def summarize_context(ctx)
          return ctx unless ctx.is_a?(Hash)

          ctx.each_with_object({}) do |(k, v), acc|
            if HEAVY_KEYS.include?(k)
              acc[k] = truncate_value(v)
            elsif k == :response && v.is_a?(Hash)
              acc[k] = v.each_with_object({}) do |(k_sub, v_sub), acc_sub|
                acc_sub[k_sub] = HEAVY_KEYS.include?(k_sub) ? truncate_value(v_sub) : v_sub
              end
            else
              acc[k] = v
            end
          end
        end

        # Truncate a value to a human-readable summary string.
        #
        # @param val [Object] The value to truncate
        # @param max_length [Integer] Maximum character length before truncation
        # @return [Object] The original value if short enough, otherwise a truncated string
        def truncate_value(val, max_length: TRUNCATE_MAX_LENGTH)
          str = val.is_a?(String) ? val : val.to_json
          return val if str.length <= max_length

          "#{str[0...max_length]}... (truncated, #{str.length} bytes)"
        end

      end
    end
  end
end
