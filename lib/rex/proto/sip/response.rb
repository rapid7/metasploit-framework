# encoding: binary

module Rex
  module Proto
    # SIP protocol support
    module SIP
      SIP_STATUS_REGEX = /^SIP\/(\d\.\d) (\d{3})\s*(.*)$/

      # Represents a generic SIP message
      class Message
        attr_accessor :headers

        def initialize
          @headers = {}
        end

        # Returns a list of all values from all +name+ headers, regardless of case,
        # or nil if no matching header is found
        def header(name)
          matches = @headers.select { |k, _| k.downcase == name.downcase }
          return nil if matches.empty?
          matches.values.flatten
        end

        # Returns a hash of header name to values mapping
        # from the provided message, or nil if no headers
        # are found
        def self.extract_headers(message)
          pairs = message.scan(/^([^\s:]+):\s*(.*)$/)
          return nil if pairs.empty?
          headers = {}
          pairs.each do |pair|
            headers[pair.first] ||= []
            headers[pair.first] << pair.last.strip
          end
          headers
        end
      end

      # Represents a SIP response message
      class Response < Message
        attr_accessor :code, :message, :status_line, :version

        # Parses +data+, constructs and returns a Response
        def self.parse(data)
          response = Response.new
          # do some basic sanity checking on this response to ensure that it is SIP
          response.status_line = data.split(/\r\n/)[0]
          unless response.status_line && response.status_line =~ SIP_STATUS_REGEX
            fail(ArgumentError, "Invalid SIP status line: #{response.status_line}")
          end
          response.version = Regexp.last_match(1)
          response.code = Regexp.last_match(2)
          response.message = Regexp.last_match(3)
          response.headers = extract_headers(data)
          response
        end
      end
    end
  end
end
