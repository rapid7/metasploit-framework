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
      'Name' => 'SAP Management Console Get Access Points',
      'Description' => %q{
        This module simply attempts to output a list of SAP access points through the
        SAP Management Console SOAP Interface.
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

    getacesspoints(ip)
  end

  def getacesspoints(rhost)
    print_status("[SAP] Connecting to SAP Management Console SOAP Interface on #{rhost}:#{rport}")
    success = false
    soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    xs = 'http://www.w3.org/2001/XMLSchema'
    sapsess = 'http://www.sap.com/webas/630/soap/features/session/'
    ns1 = 'ns1:GetAccessPointList'

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

    begin
      res = send_request_raw({
        'uri' => normalize_uri(datastore['URI']),
        'method' => 'POST',
        'data' => data,
        'headers' =>
          {
            'Content-Length' => data.length,
            'SOAPAction' => '""',
            'Content-Type' => 'text/xml; charset=UTF-8'
          }
      }, 30)

      env = []
      if res && (res.code == 200)
        case res.body
        when nil
          # Nothing
        when %r{<accesspoint>(.*)</accesspoint>}i
          body = res.body
          env = body.scan(%r{<address>(.*?)</address><port>(.*?)</port><protocol>(.*?)</protocol><processname>(.*?)</processname><active>(.*?)</active>}i)
          success = true
        end
      elsif res && (res.code == 500)
        case res.body
        when %r{<faultstring>(.*)</faultstring>}i
          faultcode = ::Regexp.last_match(1).strip
          fault = true
        end
      end
    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} [SAP] Unable to attempt authentication")
      return
    end

    if success

      saptbl = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Header' => "[SAP] Access Points #{rhost}:#{rport}",
        'Prefix' => "\n",
        'Indent' => 1,
        'Columns' =>
        [
          'address',
          'port',
          'protocol',
          'processname',
          'active'
        ]
      )

      env.each do |output|
        saptbl << [ output[0], output[1], output[2], output[3], output[4] ]
      end

      store_loot(
        'sap.getaccesspointlist',
        'text/xml',
        rhost,
        res.body,
        '.xml'
      )

      print_good("#{rhost}:#{rport} [SAP] Access Point List: #{env.length} entries extracted\n#{saptbl}")

    elsif fault
      print_error("#{rhost}:#{rport} [SAP] Error code: #{faultcode}")
    else
      print_error("#{rhost}:#{rport} [SAP] failed to request environment")
    end
  end
end
