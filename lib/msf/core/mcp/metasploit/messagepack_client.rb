# frozen_string_literal: true

require 'net/http'
require 'msgpack'

module Msf::MCP
  module Metasploit
    # MessagePack RPC client for Metasploit Framework
    # Implements authentication and API calls using MessagePack serialization
    class MessagePackClient
      DEFAULT_ENDPOINT = '/api/'

      # Initialize MessagePack client
      # @param host [String] Metasploit RPC host
      # @param port [Integer] Metasploit RPC port
      # @param endpoint [String] API endpoint path (default: DEFAULT_ENDPOINT)
      # @param ssl [Boolean] Use SSL (default: true)
      def initialize(host:, port:, endpoint: DEFAULT_ENDPOINT, ssl: true)
        @host = host
        @port = port
        @endpoint = endpoint
        @token = nil
        @http = nil
        @user = nil
        @password = nil
        @retry_count = 0
        @max_retries = 2
        @ssl = ssl
      end

      # Authenticate with Metasploit RPC
      # @param user [String] Username
      # @param password [String] Password
      # @return [String] The resulting token if authentication successful
      # @raise [AuthenticationError] If authentication fails
      def authenticate(user, password)
        # Store credentials for automatic re-authentication
        @user = user
        @password = password

        # Send authentication request directly (bypass retry logic)
        request_array = ['auth.login', user, password]
        response = send_request(request_array)

        # Real Metasploit API returns string keys
        if response['result'] == 'success' && response['token']
          @token = response['token']
        elsif response['error']
          raise AuthenticationError, response['error']
        else
          raise AuthenticationError, 'Authentication failed'
        end
      end

      # Call Metasploit RPC API method
      # @param method [String] API method name (e.g., 'module.search')
      # @param args [Array] Arguments to pass to the method (must be an array)
      # @return [Hash, Array] API response
      # @raise [AuthenticationError] If authentication fails
      # @raise [APIError] If API returns an error
      # @raise [ConnectionError] If connection fails
      # @raise [ArgumentError] If args is not an array
      def call_api(method, args = [])
        raise ArgumentError, "args must be an Array, got #{args.class}" unless args.is_a?(Array)

        begin
          raise AuthenticationError, 'Not authenticated' unless @token

          # Build request array: [method, token, *args]
          request_array = [method, @token, *args]

          # Send HTTP request
          send_request(request_array)

        rescue AuthenticationError => e
          # It is not possible to reauthenticate if we don't have credentials stored
          raise unless @user && @password
          # If reauthentication succeeded but the token is still invalid, we should not retry indefinitely
          raise unless @retry_count < @max_retries

          @retry_count += 1
          @token = nil

          begin
            wlog({ message: "#{method}': #{e.message}. Attempting to re-authenticate (#{@retry_count}/#{@max_retries})" },
                LOG_SOURCE, LOG_WARN)
            authenticate(@user, @password)
          rescue AuthenticationError => auth_e
            wlog({ message: "Re-authentication failed: #{auth_e.message}" },
                LOG_SOURCE, LOG_WARN)
            if @retry_count < @max_retries
              @retry_count += 1
              @token = nil
              retry
            end
            raise AuthenticationError, "Unable to authenticate after #{@retry_count} attempts: #{auth_e.message}"
          end

          # Retry the original request with new token
          retry
        end

      rescue Msf::MCP::Error => e
        elog({ message: 'MessagePack API call error', context: { error: e.message } },
            LOG_SOURCE, LOG_ERROR)
        raise
      ensure
        @retry_count = 0
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

      # Shutdown client and cleanup
      def shutdown
        @token = nil
        @user = nil
        @password = nil
        @http&.finish if @http&.started?
        @http = nil
      end

      private

      # Send HTTP POST request with MessagePack payload
      # @param request_array [Array] Request data
      # @return [Hash, Array] Parsed response
      # @raise [AuthenticationError] If the token is not valid
      # @raise [APIError] If the Metasploit API returns an error
      # @raise [ConnectionError] If connection fails
      def send_request(request_array)
        # Create HTTP client if needed
        unless @http
          @http = Net::HTTP.new(@host, @port)
          @http.use_ssl = @ssl
          @http.verify_mode = OpenSSL::SSL::VERIFY_NONE if @ssl
        end

        # Encode request with MessagePack
        request_body = request_array.to_msgpack

        # Create POST request
        request = Net::HTTP::Post.new(@endpoint)
        request['Content-Type'] = 'binary/message-pack'
        request.body = request_body

        dlog({
          message: 'MessagePack request',
          context: { method: request.method, endpoint: @endpoint, body: sanitize_request_array(request_array) }
        }, LOG_SOURCE, LOG_DEBUG)

        # Send request and parse response
        begin
          response = @http.request(request)

          parsed = case response.code.to_i
                   when 200
                     MessagePack.unpack(response.body)
                   when 401
                     error_data = MessagePack.unpack(response.body) rescue { 'error_message' => 'Authentication error' }
                     error_msg = error_data['error_message'] || error_data['error_string'] || 'Authentication error'
                     raise AuthenticationError, error_msg
                   when 500
                     error_data = MessagePack.unpack(response.body) rescue { 'error_message' => 'Internal server error' }
                     error_msg = error_data['error_message'] || error_data['error_string'] || 'Internal server error'
                     raise APIError, error_msg
                   else
                     raise ConnectionError, "HTTP #{response.code}: #{response.message}"
                   end

          dlog({
            message: 'MessagePack response',
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

      REDACTED = '[REDACTED]'

      # Sanitize request array for logging by redacting sensitive positional values
      #
      # For auth.login requests: redacts the password (last element)
      # For API calls: redacts the token (second element)
      #
      # @param request_array [Array] Raw request array
      # @return [Array] Sanitized copy with sensitive values redacted
      def sanitize_request_array(request_array)
        sanitized = request_array.dup
        if sanitized[0] == 'auth.login'
          sanitized[-1] = REDACTED
        elsif sanitized.length > 1
          sanitized[1] = REDACTED
        end
        sanitized
      end
    end
  end
end
