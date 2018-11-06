require 'rack/utils'

module Rack

  # Middleware that applies chunked transfer encoding to response bodies
  # when the response does not include a Content-Length header.
  class Chunked
    include Rack::Utils

    # A body wrapper that emits chunked responses
    class Body
      TERM = "\r\n"
      TAIL = "0#{TERM}#{TERM}"

      include Rack::Utils

      def initialize(body)
        @body = body
      end

      def each
        term = TERM
        @body.each do |chunk|
          size = bytesize(chunk)
          next if size == 0

          chunk = chunk.dup.force_encoding(Encoding::BINARY) if chunk.respond_to?(:force_encoding)
          yield [size.to_s(16), term, chunk, term].join
        end
        yield TAIL
      end

      def close
        @body.close if @body.respond_to?(:close)
      end
    end

    def initialize(app)
      @app = app
    end

    # pre-HTTP/1.0 (informally "HTTP/0.9") HTTP requests did not have
    # a version (nor response headers)
    def chunkable_version?(ver)
      case ver
      when "HTTP/1.0", nil, "HTTP/0.9"
        false
      else
        true
      end
    end

    def call(env)
      status, headers, body = @app.call(env)
      headers = HeaderHash.new(headers)

      if ! chunkable_version?(env['HTTP_VERSION']) ||
         STATUS_WITH_NO_ENTITY_BODY.include?(status) ||
         headers[CONTENT_LENGTH] ||
         headers['Transfer-Encoding']
        [status, headers, body]
      else
        headers.delete(CONTENT_LENGTH)
        headers['Transfer-Encoding'] = 'chunked'
        [status, headers, Body.new(body)]
      end
    end
  end
end
