# encoding: UTF-8

module Rex
  module Proto
    # SIP protocol support
    module SIP
      # Returns a list of the values for all instances of header_name from the
      # response, or nil if that header was not found
      def extract_header_values(resp, header_name)
        values = resp.scan(/^#{header_name}:\s*(.*)$/i)
        return nil if values.empty?
        values.flatten.map { |v| v.strip }.sort
      end

      # Parses +resp+, extracts useful metdata and then reports on it
      def parse_reply(resp, proto)
        rcode = resp.split(/\s+/)[0]
        # Extract the interesting headers
        metadata = {
          'agent' => extract_header_values(resp, 'User-Agent'),
          'verbs' => extract_header_values(resp, 'Allow'),
          'server' => extract_header_values(resp, 'Server'),
          'proxy' => extract_header_values(resp, 'Proxy-Require')
        }
        # Drop any that we don't retrieve
        metadata.delete_if { |_, v| v.nil? }

        print_status("#{rhost} #{rcode} #{metadata}")

        report_service(
          host: rhost,
          port: rport,
          proto: proto,
          name: 'sip'
        )

        report_note(
          host: rhost,
          type: 'sip_useragent',
          data: metadata['agent']
        ) if metadata['agent']

        report_note(
          host: rhost,
          type: 'sip_server',
          data: metadata['server']
        ) if metadata['server']
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
