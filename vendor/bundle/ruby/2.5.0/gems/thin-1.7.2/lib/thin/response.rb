module Thin
  # A response sent to the client.
  class Response
    CONNECTION     = 'Connection'.freeze
    CLOSE          = 'close'.freeze
    KEEP_ALIVE     = 'keep-alive'.freeze
    SERVER         = 'Server'.freeze
    CONTENT_LENGTH = 'Content-Length'.freeze

    PERSISTENT_STATUSES  = [100, 101].freeze

    #Error Responses
    ERROR            = [500, {'Content-Type' => 'text/plain'}, ['Internal server error']].freeze
    PERSISTENT_ERROR = [500, {'Content-Type' => 'text/plain', 'Connection' => 'keep-alive', 'Content-Length' => "21"}, ['Internal server error']].freeze
    BAD_REQUEST      = [400, {'Content-Type' => 'text/plain'}, ['Bad Request']].freeze

    # Status code
    attr_accessor :status

    # Response body, must respond to +each+.
    attr_accessor :body

    # Headers key-value hash
    attr_reader   :headers

    def initialize
      @headers    = Headers.new
      @status     = 200
      @persistent = false
      @skip_body  = false
    end

    # String representation of the headers
    # to be sent in the response.
    def headers_output
      # Set default headers
      @headers[CONNECTION] = persistent? ? KEEP_ALIVE : CLOSE unless @headers.has_key?(CONNECTION)
      @headers[SERVER]     = Thin::NAME unless @headers.has_key?(SERVER)

      @headers.to_s
    end

    # Top header of the response,
    # containing the status code and response headers.
    def head
      "HTTP/1.1 #{@status} #{HTTP_STATUS_CODES[@status.to_i]}\r\n#{headers_output}\r\n"
    end

    if Thin.ruby_18?

      # Ruby 1.8 implementation.
      # Respects Rack specs.
      #
      # See http://rack.rubyforge.org/doc/files/SPEC.html
      def headers=(key_value_pairs)
        key_value_pairs.each do |k, vs|
          vs.each { |v| @headers[k] = v.chomp } if vs
        end if key_value_pairs
      end

    else

      # Ruby 1.9 doesn't have a String#each anymore.
      # Rack spec doesn't take care of that yet, for now we just use
      # +each+ but fallback to +each_line+ on strings.
      # I wish we could remove that condition.
      # To be reviewed when a new Rack spec comes out.
      def headers=(key_value_pairs)
        key_value_pairs.each do |k, vs|
          next unless vs
          if vs.is_a?(String)
            vs.each_line { |v| @headers[k] = v.chomp }
          else
            vs.each { |v| @headers[k] = v.chomp }
          end
        end if key_value_pairs
      end

    end

    # Close any resource used by the response
    def close
      @body.close if @body.respond_to?(:close)
    end

    # Yields each chunk of the response.
    # To control the size of each chunk
    # define your own +each+ method on +body+.
    def each
      yield head

      unless @skip_body
        if @body.is_a?(String)
          yield @body
        else
          @body.each { |chunk| yield chunk }
        end
      end
    end

    # Tell the client the connection should stay open
    def persistent!
      @persistent = true
    end

    # Persistent connection must be requested as keep-alive
    # from the server and have a Content-Length, or the response
    # status must require that the connection remain open.
    def persistent?
      (@persistent && @headers.has_key?(CONTENT_LENGTH)) || PERSISTENT_STATUSES.include?(@status)
    end

    def skip_body!
      @skip_body = true
    end
  end
end
