##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'pry'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'phpMyAdmin Login Utility',
      'Description'    => %q{
        This module attempts to authenticate to a phpMyAdmin's admin web interface,
      },
      'Author'         => [ 'you' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",'' ]),
        OptPath.new('USER_FILE',  [ false, "File containing users, one per line",'' ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",'' ]),
        OptString.new('TARGETURI', [true, 'The URI path to dolibarr', '/phpMyAdmin/'])
      ], self.class)
  end


  def get_cookie_token
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => normalize_uri(datastore['TARGETURI'])
    })

    return [nil, nil] if res.nil? || res.get_cookies.empty?
    token = ''

    # Get the token ID from the body of the request
    body = res.body
    body.split("\n").each do |line|
      if line.include? 'hidden'
        line.split(';').each do |pars|
          if pars.include? 'token'
             token = pars.split('hidden" name="token" value=')[1].split('"')[1]
             break
          end
        end
      end
    end

    # Get the session ID from the cookie
    cookies = res.get_cookies.match(/phpMyAdmin/)
    pmacookie = cookies.string.split[0].split('=')[1].chomp(';')


    return pmacookie, token
  end

  def check_success(headers)

    cookarr = []
    headers['Set-Cookie'].split('y, ').each do |setcookie|
       primcookie = setcookie.split(';')[0]
       cookarr << primcookie
    end

    cookies = cookarr.join('; ')

    begin
      res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => "/#{headers['Location'].split('/')[3..-1].join('/')}",
        'cookie'   => cookies
      })
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      vprint_error("#{peer} - Service failed to respond")
      return :abort
    end
    if res.body.include? 'login'
      return false
    else
      return true
    end
  end

  def do_login(user, pass)

    pmacookie, token = get_cookie_token
    if token.nil?
      vprint_error("#{peer} - Unable to obtain session token, cannot continue")
      return :abort
    else
      vprint_status("#{peer} - Using token: #{token}")
    end

    begin
      res = send_request_cgi({
        'method'   => 'POST',
        'uri'      => normalize_uri("#{datastore['TARGETURI']}index.php"),
        'vars_post' => {
          'token'         => token,
          'server'        => '1',
          'pma_username'  => user,
          'pma_password'  => pass
        }
      })
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      vprint_error("#{peer} - Service failed to respond")
      return :abort
    end
    if res.nil?
      vprint_error("#{peer} - Connection timed out")
      return :abort
    end
    success = check_success(res.headers)
    if success
      print_good("#{peer} - Successful login: \"#{user}:#{pass}\"")
      report_auth_info({
        :host        => rhost,
        :port        => rport,
        :sname       => (ssl ? 'https' : 'http'),
        :user        => user,
        :pass        => pass,
        :source_type => 'user_supplied'
      })
      return :next_user
    else
      vprint_error("#{peer} - Bad login: \"#{user}:#{pass}\"")
      return
    end
  end

  def run_host(ip)
    each_user_pass { |user, pass|
      vprint_status("#{peer} - Trying \"#{user}:#{pass}\"")
      do_login(user, pass)
    }
  end
end
