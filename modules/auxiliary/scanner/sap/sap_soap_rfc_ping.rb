##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# Framework web site for more information on licensing and terms of use.
##

##
# This module is based on, inspired by, or is a port of a plugin available in
# the Onapsis Bizploit Opensource ERP Penetration Testing framework -
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts
# in producing the Metasploit modules and was happy to share his knowledge and
# experience - a very cool guy. I'd also like to thank Chris John Riley,
# Ian de Villiers and Joris van de Vis who have Beta tested the modules and
# provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SAP /sap/bc/soap/rfc SOAP Service RFC_PING Function Service Discovery',
      'Description' => %q{
          This module makes use of the RFC_PING function, through the	/sap/bc/soap/rfc
        SOAP service, to test connectivity to remote RFC destinations.
        },
      'References' =>
        [
          [ 'URL', 'http://labs.mwrinfosecurity.com/tools/2012/04/27/sap-metasploit-modules/' ]
        ],
      'Author' =>
        [
          'Agnivesh Sathasivam',
          'nmonkee'
        ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('CLIENT', [true, 'Client', '001']),
        OptString.new('USERNAME', [true, 'Username ', 'SAP*']),
        OptString.new('PASSWORD', [true, 'Password ', '06071992'])
      ], self.class)
  end

  def run_host(ip)
    client = datastore['CLIENT']
    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    data << '<env:Body>'
    data << '<n1:RFC_PING xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    data << '</n1:RFC_PING>'
    data << '</env:Body>'
    data << '</env:Envelope>'
    print_status("[SAP] #{ip}:#{rport} - sending SOAP RFC_PING request")
    begin
      res = send_request_cgi({
        'uri' => '/sap/bc/soap/rfc?sap-client=' + client + '&sap-language=EN',
        'method' => 'POST',
        'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + client,
        'data' => data,
        'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
        'ctype'  => 'text/xml; charset=UTF-8',
        'headers' =>
          {
            'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions'
          }
        })
      if res and res.code != 500 and res.code != 200
        if res and res.body =~ /<h1>Logon failed<\/h1>/
          print_error("[SAP] #{ip}:#{rport} - login failed!")
        else
          print_error("[SAP] #{ip}:#{rport} - something went wrong!")
        end
        return
      elsif res and res.body =~ /Response/
        print_good("[SAP] #{ip}:#{rport} - RFC service is alive")
        report_note(
          :host => ip,
          :proto => 'tcp',
          :port => rport,
          :sname => 'sap',
          :type => 'sap.services.available',
          :data => "The Remote Function Call (RFC) Service is available through the SOAP service."
        )
        return
      else
        print_status("[SAP] #{ip}:#{rport} - RFC service is not alive")
        return
      end
    rescue ::Rex::ConnectionError
      print_error("[SAP] #{ip}:#{rport} - Unable to connect")
      return
    end
  end
end
