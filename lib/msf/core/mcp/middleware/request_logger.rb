# frozen_string_literal: true

module Msf::MCP
  module Middleware
    ##
    # Rack middleware that logs MCP HTTP request/response details via Rex logging.
    #
    # Focuses on the HTTP transport layer: request method, status code, session ID,
    # content type, and round-trip timing.  For POST requests it also extracts
    # JSON-RPC fields (method, id, params) and response result/error to provide
    # DEBUG-level visibility into the exchange.
    #
    # MCP-level business details (tool names, tool durations, and structured
    # results) are handled by the SDK's +around_request+ callback configured
    # in Server, avoiding duplication.
    #
    # @example Usage in a Rack::Builder
    #   Rack::Builder.new do
    #     use Msf::MCP::Middleware::RequestLogger
    #     run transport
    #   end
    #
    class RequestLogger

      ##
      # @param app [#call] The next Rack application in the middleware stack
      #
      def initialize(app)
        @app = app
      end

      ##
      # Process the request, delegating to the next Rack app and logging
      # transport-level details after the response is produced.
      #
      # @param env [Hash] The Rack environment
      # @return [Array] The Rack response triplet [status, headers, body]
      #
      def call(env)
        request = Rack::Request.new(env)
        started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)

        response = @app.call(env)

        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at
        log_exchange(request, response, elapsed)

        response
      end

      private

      ##
      # Log a single request/response entry at the HTTP transport level.
      #
      # Dispatches to {#log_post_exchange} for POST requests (which extracts
      # JSON-RPC fields).  GET, DELETE, and other methods are logged directly
      # with status and timing information.
      #
      # @param request [Rack::Request] The incoming HTTP request
      # @param response [Array] The Rack response [status, headers, body]
      # @param elapsed [Float] Wall-clock seconds for the round-trip
      #
      def log_exchange(request, response, elapsed)
        status, headers, _body = response
        session_id = request.env['HTTP_MCP_SESSION_ID'] || headers&.fetch('Mcp-Session-Id', nil)
        elapsed_ms = (elapsed * 1000).round(2)

        context = { elapsed_ms: elapsed_ms }
        context[:session_id] = session_id if session_id

        case request.request_method
        when 'POST'
          log_post_exchange(request, response, context)
        when 'GET'
          context[:response] = build_response_context(response)
          ilog({ message: "SSE stream opened (#{elapsed_ms}ms)", context: context }, LOG_SOURCE, LOG_INFO)
        when 'DELETE'
          context[:response] = build_response_context(response)
          ilog({ message: "Session deleted (#{elapsed_ms}ms)", context: context }, LOG_SOURCE, LOG_INFO)
        else
          context[:response] = build_response_context(response)
          dlog({ message: "HTTP #{request.request_method} #{status} (#{elapsed_ms}ms)", context: context }, LOG_SOURCE, LOG_DEBUG)
        end
      end

      ##
      # Log a POST exchange with JSON-RPC params and response result/error
      # nested under :request and :response keys.
      #
      # For streaming responses (Proc body), the result is not available here —
      # it is logged by the +around_request+ callback in Server instead.
      #
      # Distinguishes between:
      # - Notifications (no id): logged at DEBUG since the SDK instrumentation
      #   does not fire for these
      # - Requests with HTTP errors: logged at ERROR with the error details
      # - Normal requests: logged at DEBUG with params and result
      #   (the +around_request+ callback provides the INFO-level business log)
      #
      # @param request [Rack::Request] The incoming HTTP request
      # @param response [Array] The Rack response [status, headers, body]
      # @param context [Hash] Pre-built context hash with session_id and elapsed_ms
      #
      def log_post_exchange(request, response, context)
        context[:request] = {}
        jsonrpc = extract_jsonrpc_fields(request)
        if jsonrpc
          context[:request][:method] = jsonrpc[:method] if jsonrpc[:method]
          context[:request][:id] = jsonrpc[:id] if jsonrpc[:id]
          context[:request][:params] = jsonrpc[:params] if jsonrpc[:params]
        end

        context[:response] = build_response_context(response)
        response_body = extract_response_body(response)
        if response_body
          context[:response][:result] = response_body[:result] if response_body[:result]
          context[:response][:error] = response_body[:error] if response_body[:error]
        end

        method_name = context[:request][:method] || 'unknown'
        if context[:request][:id].nil? && context[:request][:method]
          # Notification — no instrumentation fires for these
          dlog({ message: "Notification: #{method_name} #{context[:response][:status]} (#{context[:elapsed_ms]}ms)", context: context }, LOG_SOURCE, LOG_DEBUG)
        elsif context[:response][:status] >= 400
          elog({ message: "HTTP #{context[:response][:status]}: #{method_name} (#{context[:elapsed_ms]}ms)", context: context }, LOG_SOURCE, LOG_ERROR)
        else
          dlog({ message: "HTTP #{context[:response][:status]}: #{method_name} id=#{context[:request][:id]} (#{context[:elapsed_ms]}ms)", context: context }, LOG_SOURCE, LOG_DEBUG)
        end
      end

      ##
      # Build the response portion of the log context from the Rack response.
      #
      # @param response [Array] The Rack response [status, headers, body]
      # @return [Hash] Response context with :status and :content_type
      #
      def build_response_context(response)
        status, headers, _body = response
        res = { status: status }
        res[:content_type] = headers['Content-Type'] if headers&.key?('Content-Type')
        res
      end

      ##
      # Extract JSON-RPC method, id, and params from the request body.
      #
      # Rewinds before and after reading so downstream handlers can still
      # consume the body.
      #
      # @param request [Rack::Request] The incoming HTTP request
      # @return [Hash, nil] Parsed fields (:method, :id, :params), or nil on
      #   parse failure
      #
      def extract_jsonrpc_fields(request)
        request.body.rewind
        body = request.body.read
        request.body.rewind
        parsed = JSON.parse(body)
        { method: parsed['method'], id: parsed['id'], params: parsed['params'] }
      rescue JSON::ParserError
        nil
      end

      ##
      # Extract result or error from the response body.
      #
      # Only parses Array bodies (direct JSON responses). SSE stream responses
      # (Proc bodies) are not parseable here — their results are logged by the
      # +around_request+ callback in Server.
      #
      # @param response [Array] The Rack response [status, headers, body]
      # @return [Hash, nil] Parsed fields (:result, :error), or nil if the body
      #   is empty, non-Array, or unparseable
      #
      def extract_response_body(response)
        _status, _headers, body = response
        return nil unless body.is_a?(Array) && !body.empty?

        parsed = JSON.parse(body.first)
        { result: parsed['result'], error: parsed['error'] }
      rescue JSON::ParserError
        nil
      end
    end
  end
end
