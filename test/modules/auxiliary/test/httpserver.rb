##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Basic HttpServer Simulator',
      'Description'    => %q{
        This is example of a basic HttpServer simulator, good for PR scenarios when a module
        is made, but the author no longer has access to the test box, no pcap or screenshot -
        Basically no way to prove the functionality.

        This particular simulator will pretend to act like a Cisco ASA ASDM, so the
        cisco_asa_asdm.rb module can do a live test against it.
      },
      'References'     =>
        [
          [ 'URL', 'https://github.com/rapid7/metasploit-framework/pull/2720' ],
        ],
      'DefaultOptions' =>
        {
          'SRVPORT' => 443,
          'SSL'     => true,
          'URIPATH' => '/'
        },
      'Author'         => [ 'sinn3r' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('USERNAME', [true, "The valid default username", "cisco"]),
        OptString.new('PASSWORD', [true, "The valid default password", "cisco"])
      ], self.class)

    deregister_options('RHOST')
  end


  #
  # Returns a response when the client is trying to check the connection
  #
  def res_check_conn(cli, req)
    send_response(cli, '')
  end


  #
  # Returns a response when the client is trying to authenticate
  #
  def res_login(cli, req)
    case req.method
    when 'GET'
      # This must be the is_app_asdm? method asking
      print_status("Responding to the is_app_asdm? method")
      send_response(cli, '', {'Set-Cookie'=>'webvpn'})

    when 'POST'
      # This must be the do_login method. But before it can login, it must meet
      # the cookie requirement
      if req.headers['Cookie'] == /webvpnlogin=1; tg=0DefaultADMINGroup/
        send_redirect(cli)
        return
      end

      # Process the post data
      vars_post = {}
      req.body.scan(/(\w+=\w+)/).flatten.each do |param|
        k, v = param.split('=')
        vars_post[k] = v
      end

      # Auth
      if vars_post['username'] == datastore['USERNAME'] and vars_post['password'] == datastore['PASSWORD']
        print_good("Authenticated")

        fake_success_body = %Q|
        SSL VPN Service
        Success
        success
        |

        send_response(cli, fake_success_body)
      else
        print_error("Bad login")
        resp = create_response(403, "Access Denied")
        resp.body = ''
        cli.send_response(resp)
      end

    end
  end


  def on_request_uri(cli, req)
    print_status("Received request: #{req.uri}")

    case req.uri
      when '/'
        res_check_conn(cli, req)
      when /\+webvpn\+\/index\.html/
        res_login(cli, req)
    end

    # Request not processed, send a 404
    send_not_found(cli)
  end


  def run
    exploit
  end
end

=begin
 
Test Results - clinet output:
msf auxiliary(cisco_asa_asdm) > run

[+] 10.0.1.76:443 - Server is responsive...
[*] 10.0.1.76:443 - Application appears to be Cisco ASA ASDM. Module will continue.
[*] 10.0.1.76:443 - Starting login brute force...
[*] 10.0.1.76:443  - [1/2] - Trying username:"cisco" with password:""
[-] 10.0.1.76:443  - [1/2] - FAILED LOGIN - "cisco":""
[*] 10.0.1.76:443  - [2/2] - Trying username:"cisco" with password:"cisco"
[+] 10.0.1.76:443 - SUCCESSFUL LOGIN - "cisco":"cisco"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(cisco_asa_asdm) >

Test Results - Fake server output:

msf auxiliary(httpserver) > run

[*] Using URL: https://0.0.0.0:443/
[*]  Local IP: https://10.0.1.76:443/
[*] Server started.
[*] 10.0.1.76        httpserver - Received request: /
[*] 10.0.1.76        httpserver - Received request: /+webvpn+/index.html
[*] 10.0.1.76        httpserver - Responding to the is_app_asdm? method
[*] 10.0.1.76        httpserver - Received request: /+webvpn+/index.html
[-] 10.0.1.76        httpserver - Bad login
[*] 10.0.1.76        httpserver - Received request: /+webvpn+/index.html
[+] Authenticated
   
  
=end
