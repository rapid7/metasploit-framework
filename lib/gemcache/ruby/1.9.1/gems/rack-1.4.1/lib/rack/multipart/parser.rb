require 'rack/utils'

module Rack
  module Multipart
    class Parser
      BUFSIZE = 16384

      def initialize(env)
        @env = env
      end

      def parse
        return nil unless setup_parse

        fast_forward_to_first_boundary

        loop do
          head, filename, content_type, name, body =
            get_current_head_and_filename_and_content_type_and_name_and_body

          # Save the rest.
          if i = @buf.index(rx)
            body << @buf.slice!(0, i)
            @buf.slice!(0, @boundary_size+2)

            @content_length = -1  if $1 == "--"
          end

          filename, data = get_data(filename, body, content_type, name, head)

          Utils.normalize_params(@params, name, data) unless data.nil?

          # break if we're at the end of a buffer, but not if it is the end of a field
          break if (@buf.empty? && $1 != EOL) || @content_length == -1
        end

        @io.rewind

        @params.to_params_hash
      end

      private
      def setup_parse
        return false unless @env['CONTENT_TYPE'] =~ MULTIPART

        @boundary = "--#{$1}"

        @buf = ""
        @params = Utils::KeySpaceConstrainedParams.new

        @content_length = @env['CONTENT_LENGTH'].to_i
        @io = @env['rack.input']
        @io.rewind

        @boundary_size = Utils.bytesize(@boundary) + EOL.size

        @content_length -= @boundary_size
        true
      end

      def full_boundary
        @boundary + EOL
      end

      def rx
        @rx ||= /(?:#{EOL})?#{Regexp.quote(@boundary)}(#{EOL}|--)/n
      end

      def fast_forward_to_first_boundary
        loop do
          read_buffer = @io.gets
          break if read_buffer == full_boundary
          raise EOFError, "bad content body" if read_buffer.nil?
        end
      end

      def get_current_head_and_filename_and_content_type_and_name_and_body
        head = nil
        body = ''
        filename = content_type = name = nil
        content = nil

        until head && @buf =~ rx
          if !head && i = @buf.index(EOL+EOL)
            head = @buf.slice!(0, i+2) # First \r\n

            @buf.slice!(0, 2)          # Second \r\n

            content_type = head[MULTIPART_CONTENT_TYPE, 1]
            name = head[MULTIPART_CONTENT_DISPOSITION, 1] || head[MULTIPART_CONTENT_ID, 1]

            filename = get_filename(head)

            if filename
              body = Tempfile.new("RackMultipart")
              body.binmode  if body.respond_to?(:binmode)
            end

            next
          end

          # Save the read body part.
          if head && (@boundary_size+4 < @buf.size)
            body << @buf.slice!(0, @buf.size - (@boundary_size+4))
          end

          content = @io.read(BUFSIZE < @content_length ? BUFSIZE : @content_length)
          raise EOFError, "bad content body"  if content.nil? || content.empty?

          @buf << content
          @content_length -= content.size
        end

        [head, filename, content_type, name, body]
      end

      def get_filename(head)
        filename = nil
        if head =~ RFC2183
          filename = Hash[head.scan(DISPPARM)]['filename']
          filename = $1 if filename and filename =~ /^"(.*)"$/
        elsif head =~ BROKEN_QUOTED
          filename = $1
        elsif head =~ BROKEN_UNQUOTED
          filename = $1
        end

        if filename && filename.scan(/%.?.?/).all? { |s| s =~ /%[0-9a-fA-F]{2}/ }
          filename = Utils.unescape(filename)
        end
        if filename && filename !~ /\\[^\\"]/
          filename = filename.gsub(/\\(.)/, '\1')
        end
        filename
      end

      def get_data(filename, body, content_type, name, head)
        data = nil
        if filename == ""
          # filename is blank which means no file has been selected
          return data
        elsif filename
          body.rewind

          # Take the basename of the upload's original filename.
          # This handles the full Windows paths given by Internet Explorer
          # (and perhaps other broken user agents) without affecting
          # those which give the lone filename.
          filename = filename.split(/[\/\\]/).last

          data = {:filename => filename, :type => content_type,
                  :name => name, :tempfile => body, :head => head}
        elsif !filename && content_type && body.is_a?(IO)
          body.rewind

          # Generic multipart cases, not coming from a form
          data = {:type => content_type,
                  :name => name, :tempfile => body, :head => head}
        else
          data = body
        end

        [filename, data]
      end
    end
  end
end
