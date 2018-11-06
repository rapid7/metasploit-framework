require 'time'
require 'rack/utils'
require 'rack/mime'

module Rack
  # Rack::File serves files below the +root+ directory given, according to the
  # path info of the Rack request.
  # e.g. when Rack::File.new("/etc") is used, you can access 'passwd' file
  # as http://localhost:9292/passwd
  #
  # Handlers can detect if bodies are a Rack::File, and use mechanisms
  # like sendfile on the +path+.

  class File
    ALLOWED_VERBS = %w[GET HEAD OPTIONS]
    ALLOW_HEADER = ALLOWED_VERBS.join(', ')

    attr_accessor :root
    attr_accessor :path
    attr_accessor :cache_control

    alias :to_path :path

    def initialize(root, headers={}, default_mime = 'text/plain')
      @root = root
      @headers = headers
      @default_mime = default_mime
    end

    def call(env)
      dup._call(env)
    end

    F = ::File

    def _call(env)
      unless ALLOWED_VERBS.include? env[REQUEST_METHOD]
        return fail(405, "Method Not Allowed", {'Allow' => ALLOW_HEADER})
      end

      path_info = Utils.unescape(env[PATH_INFO])
      clean_path_info = Utils.clean_path_info(path_info)

      @path = F.join(@root, clean_path_info)

      available = begin
        F.file?(@path) && F.readable?(@path)
      rescue SystemCallError
        false
      end

      if available
        serving(env)
      else
        fail(404, "File not found: #{path_info}")
      end
    end

    def serving(env)
      if env["REQUEST_METHOD"] == "OPTIONS"
        return [200, {'Allow' => ALLOW_HEADER, CONTENT_LENGTH => '0'}, []]
      end
      last_modified = F.mtime(@path).httpdate
      return [304, {}, []] if env['HTTP_IF_MODIFIED_SINCE'] == last_modified

      headers = { "Last-Modified" => last_modified }
      headers[CONTENT_TYPE] = mime_type if mime_type

      # Set custom headers
      @headers.each { |field, content| headers[field] = content } if @headers

      response = [ 200, headers, env[REQUEST_METHOD] == "HEAD" ? [] : self ]

      size = filesize

      ranges = Rack::Utils.byte_ranges(env, size)
      if ranges.nil? || ranges.length > 1
        # No ranges, or multiple ranges (which we don't support):
        # TODO: Support multiple byte-ranges
        response[0] = 200
        @range = 0..size-1
      elsif ranges.empty?
        # Unsatisfiable. Return error, and file size:
        response = fail(416, "Byte range unsatisfiable")
        response[1]["Content-Range"] = "bytes */#{size}"
        return response
      else
        # Partial content:
        @range = ranges[0]
        response[0] = 206
        response[1]["Content-Range"] = "bytes #{@range.begin}-#{@range.end}/#{size}"
        size = @range.end - @range.begin + 1
      end

      response[2] = [response_body] unless response_body.nil?

      response[1][CONTENT_LENGTH] = size.to_s
      response
    end

    def each
      F.open(@path, "rb") do |file|
        file.seek(@range.begin)
        remaining_len = @range.end-@range.begin+1
        while remaining_len > 0
          part = file.read([8192, remaining_len].min)
          break unless part
          remaining_len -= part.length

          yield part
        end
      end
    end

    private

    def fail(status, body, headers = {})
      body += "\n"
      [
        status,
        {
          CONTENT_TYPE   => "text/plain",
          CONTENT_LENGTH => body.size.to_s,
          "X-Cascade" => "pass"
        }.merge!(headers),
        [body]
      ]
    end

    # The MIME type for the contents of the file located at @path
    def mime_type
      Mime.mime_type(F.extname(@path), @default_mime)
    end

    def filesize
      # If response_body is present, use its size.
      return Rack::Utils.bytesize(response_body) if response_body

      #   We check via File::size? whether this file provides size info
      #   via stat (e.g. /proc files often don't), otherwise we have to
      #   figure it out by reading the whole file into memory.
      F.size?(@path) || Utils.bytesize(F.read(@path))
    end

    # By default, the response body for file requests is nil.
    # In this case, the response body will be generated later
    # from the file at @path
    def response_body
      nil
    end
  end
end
