# encoding: UTF-8

require 'rex/proto/sip/util'

module Rex
  module Proto
    # SIP protocol support
    module SIP
      SIP_STATUS_REGEX = /^SIP\/(\d\.\d) (\d{3})\s*(.*)$/

      # Represents a SIP response message
      class Response
        attr_accessor :version, :code, :message, :headers

        def header(name)
          @headers.select { |k, _| k.downcase == name.downcase }.last
        end

        def self.parse(data)
          response = Response.new
          # do some basic sanity checking on this response to ensure that it is SIP
          status_line = data.split(/\r\n/)[0]
          unless status_line && status_line =~ SIP_STATUS_REGEX
            fail(ArgumentError, 'Does not start with a valid SIP status line')
          end
          response.version = Regexp.last_match(1)
          response.code = Regexp.last_match(2)
          response.message = Regexp.last_match(3)
          response.headers = ::Rex::Proto::SIP.extract_headers(data)
          response
        end
      end
    end
  end
end
