# encoding: UTF-8

require 'rex/proto/sip/response'

module Rex
  module Proto
    # SIP protocol support
    module SIP
      # Parses +response+, extracts useful metdata and then reports on it
      def parse_response(response, proto, desired_headers = %w(User-Agent Server))
        endpoint = "#{rhost}:#{rport}/#{proto}"
        begin
          options_response = Rex::Proto::SIP::Response.parse(response)
        rescue ArgumentError => e
          vprint_error("#{endpoint} is not SIP: #{e}")
          return
        end

        # We know it is SIP, so report
        report_service(
          host: rhost,
          port: rport,
          proto: proto,
          name: 'sip'
        )

        # Do header extraction as necessary
        extracted_headers = {}
        unless desired_headers.nil? || desired_headers.empty?
          desired_headers.each do |desired_header|
            next unless found_header = options_response.header(desired_header)
            extracted_headers[desired_header] ||= []
            extracted_headers[desired_header] |= found_header
          end

          # report on any extracted headers
          extracted_headers.each do |k, v|
            report_note(
              host: rhost,
              port: rport,
              proto: proto,
              type: "sip_#{k}",
              data: v
            )
          end
        end

        status = "#{endpoint} #{options_response.status_line}"
        status += ": #{extracted_headers}" unless extracted_headers.empty?
        print_status(status)
      end

      def create_probe(ip, proto)
        suser = Rex::Text.rand_text_alphanumeric(rand(8) + 1)
        shost = Rex::Socket.source_address(ip)
        src   = "#{shost}:#{datastore['RPORT']}"

        data  = "OPTIONS sip:#{datastore['TO']}@#{ip} SIP/2.0\r\n"
        data << "Via: SIP/2.0/#{proto} #{src};branch=z9hG4bK.#{format('%.8x', rand(0x100000000))};rport;alias\r\n"
        data << "From: sip:#{suser}@#{src};tag=70c00e8c\r\n"
        data << "To: sip:#{datastore['TO']}@#{ip}\r\n"
        data << "Call-ID: #{rand(0x100000000)}@#{shost}\r\n"
        data << "CSeq: 1 OPTIONS\r\n"
        data << "Contact:  sip:#{suser}@#{src}\r\n"
        data << "Max-Forwards: 20\r\n"
        data << "User-Agent: #{suser}\r\n"
        data << "Accept: text/plain\r\n"
        data << "Content-Length: 0\r\n"
        data << "\r\n"
        data
      end
    end
  end
end
