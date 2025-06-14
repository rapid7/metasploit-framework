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
      'Name' => 'SAP Management Console Instance Properties',
      'Description' => %q{
        This module simply attempts to identify the instance properties
        through the SAP Management Console SOAP Interface.
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

    enum_instance(ip)
  end

  def enum_instance(rhost)
    print_status("#{rhost}:#{rport} [SAP] Connecting to SAP Management Console SOAP Interface")
    success = false
    soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    xs = 'http://www.w3.org/2001/XMLSchema'
    sapsess = 'http://www.sap.com/webas/630/soap/features/session/'
    ns1 = 'ns1:GetInstanceProperties'

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
      }, 15)

      if res.nil?
        print_error("#{rhost}:#{rport} [SAP] Unable to connect")
        return
      end

      if res.code == 200
        body = res.body
        if body.match(%r{<property>CentralServices</property><propertytype>Attribute</propertytype><value>([^<]+)</value>})
          centralservices = ::Regexp.last_match(1).strip
          success = true
        end
        if body.match(%r{<property>SAPSYSTEM</property><propertytype>Attribute</propertytype><value>([^<]+)</value>})
          sapsystem = ::Regexp.last_match(1).strip
          success = true
        end
        if body.match(%r{<property>SAPSYSTEMNAME</property><propertytype>Attribute</propertytype><value>([^<]+)</value>})
          sapsystemname = ::Regexp.last_match(1).strip
          success = true
        end
        if body.match(%r{<property>SAPLOCALHOST</property><propertytype>Attribute</propertytype><value>([^<]+)</value>})
          saplocalhost = ::Regexp.last_match(1).strip
          success = true
        end
        if body.match(%r{<property>INSTANCE_NAME</property><propertytype>Attribute</propertytype><value>([^<]+)</value>})
          instancename = ::Regexp.last_match(1).strip
          success = true
        end
        if body.match(%r{<property>ICM</property><propertytype>NodeURL</propertytype><value>([^<]+)</value>})
          icmurl = ::Regexp.last_match(1).strip
          success = true
        end
        if body.match(%r{<property>IGS</property><propertytype>NodeURL</propertytype><value>([^<]+)</value>})
          igsurl = ::Regexp.last_match(1).strip
          success = true
        end
        if body.match(%r{<property>ABAP DB Connection</property><propertytype>Attribute</propertytype><value>([^<]+)</value>})
          dbstring = ::Regexp.last_match(1).strip
          success = true
        end
        if body.match(%r{<property>J2EE DB Connection</property><propertytype>Attribute</propertytype><value>([^<]+)</value>})
          j2eedbstring = ::Regexp.last_match(1).strip
          success = true
        end
        if body.match(%r{<property>Webmethods</property><propertytype>Attribute</propertytype><value>([^<]+)</value>})
          webmethods = ::Regexp.last_match(1).strip
          success = true
        end
        if body.match(%r{<property>Protected Webmethods</property><propertytype>Attribute</propertytype><value>([^<]+)</value>})
          protectedweb = ::Regexp.last_match(1).strip
          success = true
        end
      elsif res.code == 500
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

    if fault
      print_error("#{rhost}:#{rport} [SAP] Error code: #{faultcode}")
      return
    end

    unless success
      print_error("#{rhost}:#{rport} [SAP] Failed to identify instance properties")
      return
    end

    print_good("#{rhost}:#{rport} [SAP] Instance Properties Extracted")
    if centralservices
      print_good("#{rhost}:#{rport} [SAP] Central Services: #{centralservices}")
    end
    if sapsystem
      print_good("#{rhost}:#{rport} [SAP] SAP System Number: #{sapsystem}")
      report_note(host: rhost,
                  proto: 'tcp',
                  port: rport,
                  type: 'sap.sapsystem',
                  data: { proto: 'soap', sapsystem: sapsystem })
    end
    if sapsystemname
      print_good("#{rhost}:#{rport} [SAP] SAP System Name: #{sapsystemname}")
      report_note(host: rhost,
                  proto: 'tcp',
                  port: rport,
                  type: 'sap.systemname',
                  data: { proto: 'soap', sapsystemname: sapsystemname })
    end
    if saplocalhost
      print_good("#{rhost}:#{rport} [SAP] SAP Localhost: #{saplocalhost}")
      report_note(host: rhost,
                  proto: 'tcp',
                  port: rport,
                  type: 'sap.localhost',
                  data: { proto: 'soap', saplocalhost: saplocalhost })
    end
    if instancename
      print_good("#{rhost}:#{rport} [SAP] Instance Name: #{instancename}")
      report_note(host: rhost,
                  proto: 'tcp',
                  port: rport,
                  type: 'sap.instancename',
                  data: { proto: 'soap', instancename: instancename })
    end
    if icmurl
      print_good("#{rhost}:#{rport} [SAP] ICM URL: #{icmurl}")
      report_note(host: rhost,
                  proto: 'tcp',
                  port: rport,
                  type: 'sap.icm.url',
                  data: { proto: 'soap', icmurl: icmurl })
    end
    if igsurl
      print_good("#{rhost}:#{rport} [SAP] IGS URL: #{igsurl}")
      report_note(host: rhost,
                  proto: 'tcp',
                  port: rport,
                  type: 'sap.igs.url',
                  data: { proto: 'soap', igsurl: igsurl })
    end
    if dbstring
      print_good("#{rhost}:#{rport} [SAP] ABAP DATABASE: #{dbstring}")
      report_note(host: rhost,
                  proto: 'tcp',
                  port: rport,
                  type: 'sap.dbstring',
                  data: { proto: 'soap', dbstring: dbstring },
                  update: :unique_data)
    end
    if j2eedbstring
      print_good("#{rhost}:#{rport} [SAP] J2EE DATABASE: #{j2eedbstring}")
      report_note(host: rhost,
                  proto: 'tcp',
                  port: rport,
                  type: 'sap.j2eedbstring',
                  data: { proto: 'soap', j2eedbstring: j2eedbstring },
                  update: :unique_data)
    end
    if protectedweb
      protectedweb_arr = protectedweb.split(',')
      print_good("#{rhost}:#{rport} [SAP] Protected Webmethods (auth required) :::")
      print_status(protectedweb.to_s)
      report_note(host: rhost,
                  proto: 'tcp',
                  port: rport,
                  type: 'sap.protected.web.methods',
                  data: { proto: 'soap', protectedweb: protectedweb },
                  update: :unique_data)
    end
    if webmethods
      webmethods_output = [] # create empty webmethods array
      webmethods_arr = webmethods.split(',')
      webmethods_arr.each do |webm|
        # Only add webmethods not found in protectedweb_arr
        webmethods_output << webm unless protectedweb_arr && protectedweb_arr.include?(webm)
      end
      if webmethods_output
        print_good("#{rhost}:#{rport} [SAP] Unprotected Webmethods :::")
        print_status(webmethods_output.join(',').to_s)
      end
      report_note(host: rhost,
                  proto: 'tcp',
                  port: rport,
                  type: 'sap.web.methods',
                  data: { proto: 'soap', webmethods: webmethods },
                  update: :unique_data)
    end
  end
end
