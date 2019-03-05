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
      'Name'         => 'SAP Management Console Version Detection',
      'Description'  => %q{
        This module simply attempts to identify the version of SAP
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
  end

  def run_host(ip)
    res = send_request_cgi({
      'uri'	 => normalize_uri(datastore['URI']),
      'method'  => 'GET'
    }, 25)

    if not res
      print_error("#{rhost}:#{rport} [SAP] Unable to connect")
      return
    end

    enum_version(ip)
  end

  def enum_version(rhost)
    print_status("[SAP] Connecting to SAP Management Console SOAP Interface on #{rhost}:#{rport}")
    success = false
    soapenv='http://schemas.xmlsoap.org/soap/envelope/'
    xsi='http://www.w3.org/2001/XMLSchema-instance'
    xs='http://www.w3.org/2001/XMLSchema'
    sapsess='http://www.sap.com/webas/630/soap/features/session/'
    ns1='ns1:GetVersionInfo'

    data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi + '" xmlns:xs="' + xs + '">' + "\r\n"
    data << '<SOAP-ENV:Header>' + "\r\n"
    data << '<sapsess:Session xlmns:sapsess="' +  sapsess + '">' + "\r\n"
    data << '<enableSession>true</enableSession>' + "\r\n"
    data << '</sapsess:Session>' + "\r\n"
    data << '</SOAP-ENV:Header>' + "\r\n"
    data << '<SOAP-ENV:Body>' + "\r\n"
    data << '<'+ ns1 + ' xmlns:ns1="urn:SAPControl"></' + ns1 +'>' + "\r\n"
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

      if res and res.code == 200
        body = res.body
        if body.match(/<VersionInfo>([^<]+)<\/VersionInfo>/)
          version = $1
          success = true
        end
        if body.match(/[\\\/]sap[\\\/](\w{3})/i)
          sapsid = $1
          success = true
        else
          sapsid = "Unknown"
        end
      elsif res and res.code == 500
        case res.body
        when /<faultstring>(.*)<\/faultstring>/i
            faultcode = $1
            fault = true
        end
      end

    rescue ::Rex::ConnectionError
      print_error("[SAP #{rhost}] Unable to attempt authentication")
      return :abort
    end

    if success
      print_good("[SAP] Version Number Extracted - #{rhost}:#{rport}")
      print_good("[SAP] Version: #{version}")
      print_good("[SAP] SID: #{sapsid.upcase}")

      report_note(
        :host => rhost,
        :proto => 'SOAP',
        :port => rport,
        :type => 'SAP Version',
        :data => "SAP Version: #{version}"
      )

      report_note(
        :host => rhost,
        :proto => 'SOAP',
        :port => rport,
        :type => 'SAP SID',
        :data => "SAP SID: #{sapsid.upcase}"
      )

      return
    elsif fault
      print_error("[SAP] Error code: #{faultcode}")
      return
    else
      print_error("[SAP] failed to identify version")
      return
    end
  end
end
