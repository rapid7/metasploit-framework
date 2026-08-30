# frozen_string_literal: true

require 'net/http'
require 'json'

module Msf::MCP
  module Metasploit
    # JSON-RPC 2.0 client for Metasploit Framework
    # Implements bearer token authentication for the Metasploit JSON-RPC API
    # Endpoint: /api/v1/json-rpc (default port 8081)
    # See: lib/msf/core/rpc/json/ in Metasploit Framework repository
    class JsonRpcClient
      DEFAULT_ENDPOINT = '/api/v1/json-rpc'

      # Initialize JSON-RPC client
      # @param host [String] Metasploit RPC host
      # @param port [Integer] Metasploit RPC port
      # @param endpoint [String] API endpoint path (default: DEFAULT_ENDPOINT)
      # @param token [String] Bearer authentication token
      # @param ssl [Boolean] Use SSL (default: true)
      def initialize(host:, port:, endpoint: DEFAULT_ENDPOINT, token:, ssl: true)
        @host = host
        @port = port
        @endpoint = endpoint
        @token = token
        @request_id = 0
        @http = nil
        @ssl = ssl
      end

      # No-op for JSON-RPC: authentication uses a pre-configured bearer token.
      # This method exists so that JsonRpcClient satisfies the same interface as
      # MessagePackClient, allowing the Client facade to delegate uniformly.
      #
      # @param _user [String] Ignored
      # @param _password [String] Ignored
      # @return [String] The existing token
      def authenticate(_user, _password)
        @token
      end

      # Call Metasploit API method using JSON-RPC 2.0 format
      # @param method [String] API method name
      # @param args [Array] Arguments to pass to the method (must be an array)
      # @return [Hash] API response
      # @raise [AuthenticationError] If token is invalid
      # @raise [APIError] If API returns error
      # @raise [ConnectionError] If connection fails
      # @raise [ArgumentError] If args is not an array
      def call_api(method, args = [])
        raise ArgumentError, "args must be an Array, got #{args.class}" unless args.is_a?(Array)

        @request_id += 1

        # Build JSON-RPC 2.0 request as a hash
        request_body = {
          jsonrpc: '2.0',
          method: method,
          params: args,
          id: @request_id
        }

        # Send HTTP request
        response = send_request(request_body)

        # Check for JSON-RPC error
        if response['error']
          error_msg = response['error']['message'] || 'Unknown error'
          raise APIError, error_msg
        end

        response['result']
      end

      # Search for Metasploit modules
      # @param query [String] Search query
      # @return [Array<Hash>] Module metadata
      def search_modules(query)
        call_api('module.search', [query])
      end

      # Get module information
      # @param type [String] Module type ('exploit', 'auxiliary', 'post', etc.)
      # @param name [String] Module name
      # @return [Hash] Module information
      def module_info(type, name)
        call_api('module.info', [type, name])
      end

      # Get hosts from database
      # @param options [Hash] Query options (workspace, limit, offset, etc.)
      # @return [Hash] Response with 'hosts' array
      def db_hosts(options = {})
        call_api('db.hosts', [options])
      end

      # Get services from database
      # @param options [Hash] Query options
      # @return [Hash] Response with 'services' array
      def db_services(options = {})
        call_api('db.services', [options])
      end

      # Get vulnerabilities from database
      # @param options [Hash] Query options
      # @return [Hash] Response with 'vulns' array
      def db_vulns(options = {})
        call_api('db.vulns', [options])
      end

      # Get notes from database
      # @param options [Hash] Query options
      # @return [Hash] Response with 'notes' array
      def db_notes(options = {})
        call_api('db.notes', [options])
      end

      # Get credentials from database
      # @param options [Hash] Query options
      # @return [Hash] Response with 'creds' array
      def db_creds(options = {})
        call_api('db.creds', [options])
      end

      # Get loot from database
      # @param options [Hash] Query options
      # @return [Hash] Response with 'loots' array
      def db_loot(options = {})
        call_api('db.loots', [options])
      end

      # Execute a Metasploit module
      # @param type [String] Module type ('exploit', 'auxiliary', 'post', 'payload', 'evasion')
      # @param name [String] Module name (e.g. 'multi/handler')
      # @param options [Hash] Module datastore options
      # @return [Hash] Response containing 'job_id' and 'uuid' keys
      def module_execute(type, name, options = {})
        call_api('module.execute', [type, name, options])
      end

      # Run the check method of a Metasploit module
      # @param type [String] Module type ('exploit' or 'auxiliary')
      # @param name [String] Module name
      # @param options [Hash] Module datastore options
      # @return [Hash] Response containing 'job_id' and 'uuid' keys
      def module_check(type, name, options = {})
        call_api('module.check', [type, name, options])
      end

      # Get module execution results by UUID
      # @param uuid [String] Module run UUID returned by module_execute / module_check
      # @return [Hash] Result hash with 'status' key (and 'result' / 'error' as applicable)
      def module_results(uuid)
        call_api('module.results', [uuid])
      end

      # Get currently running module stats (waiting / running / results)
      # @return [Hash] Hash with 'waiting', 'running', 'results' arrays of UUIDs
      def running_stats
        call_api('module.running_stats', [])
      end

      # List active sessions
      # @return [Hash] Hash keyed by session ID with session info hashes as values
      def session_list
        call_api('session.list', [])
      end

      # Stop (kill) an active session
      # @param session_id [Integer] Session ID
      # @return [Hash] Response with 'result' key set to 'success'
      def session_stop(session_id)
        call_api('session.stop', [session_id])
      end

      # Read buffered output from an interactive session (meterpreter, DB, SMB)
      # @param session_id [Integer] Session ID
      # @return [Hash] Response with 'data' key containing the buffered output
      def session_read(session_id)
        call_api('session.interactive_read', [session_id])
      end

      # Send input to an interactive session
      # @param session_id [Integer] Session ID
      # @param data [String] Data to send to the session
      # @return [Hash] Response with 'result' key
      def session_write(session_id, data)
        call_api('session.interactive_write', [session_id, data])
      end

      # Shutdown client
      def shutdown
        @http&.finish if @http&.started?
        @http = nil
      end

      private

      # Send HTTP POST request with JSON-RPC payload
      # @param request_body [Hash] JSON-RPC request body as a hash
      # @return [Hash] Parsed response
      # @raise [ConnectionError] If connection fails
      # @raise [AuthenticationError] If token is invalid
      def send_request(request_body)
        # Create HTTP client if needed
        unless @http
          @http = Net::HTTP.new(@host, @port)
          @http.use_ssl = @ssl
          @http.verify_mode = OpenSSL::SSL::VERIFY_NONE if @ssl
        end

        # Create POST request
        request = Net::HTTP::Post.new(@endpoint)
        request['Content-Type'] = 'application/json'
        request['Authorization'] = "Bearer #{@token}"
        request.body = request_body.to_json

        dlog({
          message: 'JSON-RPC request',
          context: { method: request.method, endpoint: @endpoint, body: request_body }
        }, LOG_SOURCE, LOG_DEBUG)

        # Send request and parse response
        begin
          response = @http.request(request)

          parsed = case response.code.to_i
                   when 200
                     JSON.parse(response.body)
                   when 401
                     raise AuthenticationError, 'Invalid authentication token'
                   when 500
                     error_data = JSON.parse(response.body) rescue { 'error' => { 'message' => 'Internal server error' } }
                     error_msg = error_data.dig('error', 'message') || 'Internal server error'
                     raise APIError, error_msg
                   else
                     raise ConnectionError, "HTTP #{response.code}: #{response.message}"
                   end

          dlog({
            message: 'JSON-RPC response',
            context: { status: response.code, body: parsed }
          }, LOG_SOURCE, LOG_DEBUG)

          parsed
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
          raise ConnectionError, "Cannot connect to Metasploit RPC: #{e.message}"
        rescue SocketError => e
          raise ConnectionError, "Network error: #{e.message}"
        rescue Timeout::Error => e
          raise ConnectionError, "Request timeout: #{e.message}"
        rescue EOFError => e
          raise ConnectionError, "Empty response from Metasploit RPC: #{e.message}"
        end
      end
    end
  end
end
